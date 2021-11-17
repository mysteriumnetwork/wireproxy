package main

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"io/ioutil"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/mysteriumnetwork/wireproxy/auth"
	"github.com/mysteriumnetwork/wireproxy/logger"
	"github.com/mysteriumnetwork/wireproxy/proxy"
)

var (
	version = "undefined"
)

func perror(msg string) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, msg)
}

func arg_fail(msg string) {
	perror(msg)
	perror("Usage:")
	flag.PrintDefaults()
	os.Exit(2)
}

type CLIArgs struct {
	bind_address      string
	auth              string
	verbosity         int
	timeout           time.Duration
	cert, key, cafile string
	list_ciphers      bool
	ciphers           string
	disableHTTP2      bool
	showVersion       bool
}

func list_ciphers() {
	for _, cipher := range tls.CipherSuites() {
		fmt.Println(cipher.Name)
	}
}

func parse_args() CLIArgs {
	var args CLIArgs
	flag.StringVar(&args.bind_address, "bind-address", ":8080", "HTTP proxy listen address")
	flag.StringVar(&args.auth, "auth", "none://", "auth parameters")
	flag.IntVar(&args.verbosity, "verbosity", 20, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	flag.DurationVar(&args.timeout, "timeout", 10*time.Second, "timeout for network operations")
	flag.StringVar(&args.cert, "cert", "", "enable TLS and use certificate")
	flag.StringVar(&args.key, "key", "", "key for TLS certificate")
	flag.StringVar(&args.cafile, "cafile", "", "CA file to authenticate clients with certificates")
	flag.BoolVar(&args.list_ciphers, "list-ciphers", false, "list ciphersuites")
	flag.StringVar(&args.ciphers, "ciphers", "", "colon-separated list of enabled ciphers")
	flag.BoolVar(&args.disableHTTP2, "disable-http2", false, "disable HTTP2")
	flag.BoolVar(&args.showVersion, "version", false, "show program version and exit")
	flag.Parse()
	return args
}

func run() int {
	args := parse_args()

	if args.showVersion {
		fmt.Println(version)
		return 0
	}

	if args.list_ciphers {
		list_ciphers()
		return 0
	}

	logWriter := logger.NewLogWriter(os.Stderr)
	defer logWriter.Close()

	mainLogger := logger.NewCondLogger(log.New(logWriter, "MAIN    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	proxyLogger := logger.NewCondLogger(log.New(logWriter, "PROXY   : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)

	auth, err := auth.NewAuth(args.auth)
	if err != nil {
		mainLogger.Critical("Failed to instantiate auth provider: %v", err)
		return 3
	}

	server := http.Server{
		Addr:              args.bind_address,
		Handler:           proxy.NewProxyHandler(args.timeout, auth, new(net.Dialer).DialContext, proxyLogger),
		ErrorLog:          log.New(logWriter, "HTTPSRV : ", log.LstdFlags|log.Lshortfile),
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
	}

	if args.disableHTTP2 {
		server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}

	mainLogger.Info("Starting proxy server...")
	if args.cert != "" {
		cfg, err1 := makeServerTLSConfig(args.cert, args.key, args.cafile)
		if err1 != nil {
			mainLogger.Critical("TLS config construction failed: %v", err1)
			return 3
		}
		cfg.CipherSuites = makeCipherList(args.ciphers)
		server.TLSConfig = cfg
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	mainLogger.Critical("Server terminated with a reason: %v", err)
	mainLogger.Info("Shutting down...")
	return 0
}

func main() {
	os.Exit(run())
}

func makeServerTLSConfig(certfile, keyfile, cafile string) (*tls.Config, error) {
	var cfg tls.Config
	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	cfg.Certificates = []tls.Certificate{cert}
	if cafile != "" {
		roots := x509.NewCertPool()
		certs, err := ioutil.ReadFile(cafile)
		if err != nil {
			return nil, err
		}
		if ok := roots.AppendCertsFromPEM(certs); !ok {
			return nil, errors.New("Failed to load CA certificates")
		}
		cfg.ClientCAs = roots
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return &cfg, nil
}

func makeCipherList(ciphers string) []uint16 {
	if ciphers == "" {
		return nil
	}

	cipherIDs := make(map[string]uint16)
	for _, cipher := range tls.CipherSuites() {
		cipherIDs[cipher.Name] = cipher.ID
	}

	cipherNameList := strings.Split(ciphers, ":")
	cipherIDList := make([]uint16, 0, len(cipherNameList))

	for _, name := range cipherNameList {
		id, ok := cipherIDs[name]
		if !ok {
			log.Printf("WARNING: Unknown cipher \"%s\"", name)
		}
		cipherIDList = append(cipherIDList, id)
	}

	return cipherIDList
}
