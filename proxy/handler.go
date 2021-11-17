package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mysteriumnetwork/wireproxy/auth"
	"github.com/mysteriumnetwork/wireproxy/logger"
)

type ContextDialer func (context.Context, string, string) (net.Conn, error)

type ProxyHandler struct {
	timeout       time.Duration
	auth          auth.Auth
	logger        *logger.CondLogger
	httptransport http.RoundTripper
	outbound      map[string]string
	outboundMux   sync.RWMutex
	dialer        ContextDialer
}

func NewProxyHandler(timeout time.Duration, auth auth.Auth, dialer ContextDialer, logger *logger.CondLogger) *ProxyHandler {
	httptransport := &http.Transport{
		DialContext: dialer,
	}
	return &ProxyHandler{
		timeout:       timeout,
		auth:          auth,
		logger:        logger,
		httptransport: httptransport,
		outbound:      make(map[string]string),
		dialer:        dialer,
	}
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request) {
	ctx, _ := context.WithTimeout(req.Context(), s.timeout)
	conn, err := s.dialer(ctx, "tcp", req.RequestURI)
	if err != nil {
		s.logger.Error("Can't satisfy CONNECT request: %v", err)
		http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
		return
	}

	localAddr := conn.LocalAddr().String()
	s.outboundMux.Lock()
	s.outbound[localAddr] = req.RemoteAddr
	s.outboundMux.Unlock()
	defer func() {
		conn.Close()
		s.outboundMux.Lock()
		delete(s.outbound, localAddr)
		s.outboundMux.Unlock()
	}()

	if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
		// Upgrade client connection
		localconn, _, err := hijack(wr)
		if err != nil {
			s.logger.Error("Can't hijack client connection: %v", err)
			http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
			return
		}
		defer localconn.Close()

		// Inform client connection is built
		fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)

		proxy(req.Context(), localconn, conn)
	} else if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		proxyh2(req.Context(), req.Body, wr, conn)
	} else {
		s.logger.Error("Unsupported protocol version: %s", req.Proto)
		http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
		return
	}
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request) {
	req.RequestURI = ""
	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http" // We can't access :scheme pseudo-header, so assume http
		req.URL.Host = req.Host
	}
	resp, err := s.httptransport.RoundTrip(req)
	if err != nil {
		s.logger.Error("HTTP fetch error: %v", err)
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	s.logger.Info("%v %v %v %v", req.RemoteAddr, req.Method, req.URL, resp.Status)
	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	flush(wr)
	copyBody(wr, resp.Body)
}

func (s *ProxyHandler) isLoopback(req *http.Request) (string, bool) {
	s.outboundMux.RLock()
	originator, found := s.outbound[req.RemoteAddr]
	s.outboundMux.RUnlock()
	return originator, found
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v %v", req.RemoteAddr, req.Proto, req.Method, req.URL)

	if originator, isLoopback := s.isLoopback(req); isLoopback {
		s.logger.Critical("Loopback tunnel detected: %s is an outbound "+
			"address for another request from %s", req.RemoteAddr, originator)
		http.Error(wr, auth.BAD_REQ_MSG, http.StatusBadRequest)
		return
	}

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 ||
		req.Host == "" && req.ProtoMajor == 2 {
		http.Error(wr, auth.BAD_REQ_MSG, http.StatusBadRequest)
		return
	}
	if !s.auth.Validate(wr, req) {
		return
	}
	delHopHeaders(req.Header)
	if isConnect {
		s.HandleTunnel(wr, req)
	} else {
		s.HandleRequest(wr, req)
	}
}
