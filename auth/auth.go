package auth

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const AUTH_REQUIRED_MSG = "Proxy authentication required.\n"
const BAD_REQ_MSG = "Bad Request\n"
const AUTH_TRIGGERED_MSG = "Browser auth triggered!\n"
const EPOCH_EXPIRE = "Thu, 01 Jan 1970 00:00:01 GMT"

type Auth interface {
	Validate(wr http.ResponseWriter, req *http.Request) bool
}

func NewAuth(paramstr string) (Auth, error) {
	url, err := url.Parse(paramstr)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(url.Scheme) {
	case "static":
		return NewStaticAuth(url)
	case "basicfile":
		return NewBasicFileAuth(url)
	case "cert":
		return CertAuth{}, nil
	case "none":
		return NoAuth{}, nil
	default:
		return nil, errors.New("Unknown auth scheme")
	}
}

func NewStaticAuth(param_url *url.URL) (*BasicAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	username := values.Get("username")
	if username == "" {
		return nil, errors.New("\"username\" parameter is missing from auth config URI")
	}
	password := values.Get("password")
	if password == "" {
		return nil, errors.New("\"password\" parameter is missing from auth config URI")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return nil, err
	}
	return &BasicAuth{
		users: map[string][]byte{
			username: hashedPassword,
		},
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
	}, nil
}

func requireBasicAuth(wr http.ResponseWriter, req *http.Request, hidden_domain string) {
	if hidden_domain != "" &&
		(subtle.ConstantTimeCompare([]byte(req.URL.Host), []byte(hidden_domain)) != 1 &&
			subtle.ConstantTimeCompare([]byte(req.Host), []byte(hidden_domain)) != 1) {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
	} else {
		wr.Header().Set("Proxy-Authenticate", `Basic realm="dumbproxy"`)
		wr.Header().Set("Content-Length", strconv.Itoa(len([]byte(AUTH_REQUIRED_MSG))))
		wr.WriteHeader(407)
		wr.Write([]byte(AUTH_REQUIRED_MSG))
	}
}

type BasicAuth struct {
	users        map[string][]byte
	hiddenDomain string
}

func NewBasicFileAuth(param_url *url.URL) (*BasicAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	filename := values.Get("path")
	if filename == "" {
		return nil, errors.New("\"path\" parameter is missing from auth config URI")
	}

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	users := make(map[string][]byte)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		pair := strings.SplitN(line, ":", 2)
		if len(pair) != 2 {
			return nil, errors.New("Malformed login and password line")
		}
		login := pair[0]
		password := pair[1]
		users[login] = []byte(password)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, errors.New("No password lines were read from file")
	}
	return &BasicAuth{
		users:        users,
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
	}, nil
}

func (auth *BasicAuth) Validate(wr http.ResponseWriter, req *http.Request) bool {
	hdr := req.Header.Get("Proxy-Authorization")
	if hdr == "" {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return false
	}
	hdr_parts := strings.SplitN(hdr, " ", 2)
	if len(hdr_parts) != 2 || strings.ToLower(hdr_parts[0]) != "basic" {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return false
	}

	token := hdr_parts[1]
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return false
	}

	pair := strings.SplitN(string(data), ":", 2)
	if len(pair) != 2 {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return false
	}

	login := pair[0]
	password := pair[1]

	hashedPassword, ok := auth.users[login]
	if !ok {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return false
	}

	if bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)) == nil {
		if auth.hiddenDomain != "" &&
			(req.Host == auth.hiddenDomain || req.URL.Host == auth.hiddenDomain) {
			wr.Header().Set("Content-Length", strconv.Itoa(len([]byte(AUTH_TRIGGERED_MSG))))
			wr.Header().Set("Pragma", "no-cache")
			wr.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			wr.Header().Set("Expires", EPOCH_EXPIRE)
			wr.Header()["Date"] = nil
			wr.WriteHeader(http.StatusOK)
			wr.Write([]byte(AUTH_TRIGGERED_MSG))
			return false
		} else {
			return true
		}
	}
	requireBasicAuth(wr, req, auth.hiddenDomain)
	return false
}

type NoAuth struct{}

func (_ NoAuth) Validate(wr http.ResponseWriter, req *http.Request) bool {
	return true
}

type CertAuth struct{}

func (_ CertAuth) Validate(wr http.ResponseWriter, req *http.Request) bool {
	if req.TLS == nil || len(req.TLS.VerifiedChains) < 1 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return false
	} else {
		return true
	}
}
