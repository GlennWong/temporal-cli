package devserver

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const bearerPrefix = "Bearer "

// authorized reports whether header carries the bearer token.
func authorized(header, token string) bool {
	if token == "" || !strings.HasPrefix(header, bearerPrefix) {
		return false
	}
	got := strings.TrimPrefix(header, bearerPrefix)
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

type authProxy struct {
	srv *http.Server
}

// stop closes the auth proxy listener.
func (p *authProxy) stop() { _ = p.srv.Close() }

// startAuthProxy listens on listenAddr and forwards gRPC (HTTP/2 cleartext) to
// upstream, requiring "authorization: Bearer <token>" on every request.
func startAuthProxy(listenAddr, upstream, token string, logger *slog.Logger) (*authProxy, error) {
	target, err := url.Parse("http://" + upstream)
	if err != nil {
		return nil, err
	}
	proto := new(http.Protocols)
	proto.SetUnencryptedHTTP2(true)
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &http.Transport{Protocols: proto}
	rp.FlushInterval = -1 // stream gRPC messages
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r.Header.Get("Authorization"), token) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "16") // Unauthenticated
			w.Header().Set("Grpc-Message", "unauthenticated")
			w.WriteHeader(http.StatusOK)
			return
		}
		r.Header.Del("Authorization") // do not leak the token upstream
		rp.ServeHTTP(w, r)
	})
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: handler, Protocols: proto}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("auth proxy stopped", "error", err)
		}
	}()
	return &authProxy{srv: srv}, nil
}
