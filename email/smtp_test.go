package email

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"
)

type smtpResult struct {
	commands []string
	data     string
	err      error
}

// A local TLS SMTP peer exercises the real network protocol without delivery.
func smtpPeer(t *testing.T, mode string, advertiseTLS bool) (string, int, *x509.CertPool, <-chan smtpResult) {
	t.Helper()
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	leaf := fixture.Certificate()
	fixture.Close()
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	results := make(chan smtpResult, 1)
	go func() {
		result := smtpResult{}
		defer func() { results <- result }()
		conn, err := listener.Accept()
		if err != nil {
			result.err = err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		secure := false
		if mode == "tls" {
			conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			secure = true
		}
		reader := textproto.NewReader(bufio.NewReader(conn))
		write := func(line string) bool {
			_, err := fmt.Fprint(conn, line)
			if err != nil {
				result.err = err
				return false
			}
			return true
		}
		if !write("220 local SMTP test\r\n") {
			return
		}
		for {
			line, err := reader.ReadLine()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					result.err = err
				}
				return
			}
			result.commands = append(result.commands, line)
			switch {
			case strings.HasPrefix(line, "EHLO "):
				capabilities := "250-localhost\r\n"
				if !secure && advertiseTLS {
					capabilities += "250-STARTTLS\r\n"
				}
				capabilities += "250 AUTH PLAIN\r\n"
				if !write(capabilities) {
					return
				}
			case line == "STARTTLS":
				if !write("220 Go ahead\r\n") {
					return
				}
				conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				reader = textproto.NewReader(bufio.NewReader(conn))
				secure = true
			case strings.HasPrefix(line, "AUTH PLAIN "):
				if !secure {
					result.err = errors.New("credentials sent without TLS")
					return
				}
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
				if err != nil || string(decoded) != "\x00user\x00secret" {
					result.err = errors.New("wrong SMTP authentication payload")
					return
				}
				if !write("235 Authenticated\r\n") {
					return
				}
			case strings.HasPrefix(line, "MAIL FROM:") || strings.HasPrefix(line, "RCPT TO:"):
				if !secure {
					result.err = errors.New("envelope sent without TLS")
					return
				}
				if !write("250 OK\r\n") {
					return
				}
			case line == "DATA":
				if !write("354 End with dot\r\n") {
					return
				}
				data, err := io.ReadAll(reader.DotReader())
				if err != nil {
					result.err = err
					return
				}
				result.data = string(data)
				if !write("250 Accepted\r\n") {
					return
				}
			case line == "QUIT":
				write("221 Bye\r\n")
				return
			default:
				result.err = fmt.Errorf("unexpected SMTP command %q", line)
				return
			}
		}
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	return host, port, pool, results
}

func TestSMTPVerifiedTLSAndMIME(t *testing.T) {
	for _, mode := range []string{"tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			host, port, roots, results := smtpPeer(t, mode, true)
			c := testConfig("smtp")
			c.SMTP.Host = host
			c.SMTP.Port = port
			c.SMTP.TLSMode = mode
			s := &sender{config: c, transport: &smtpTransport{config: c, rootCAs: roots}}
			m := Message{To: "recipient@example.com", Subject: "你好 test", Text: "hello\n.line\n名字", HTML: "<p>名字</p>"}
			if err := s.Send(t.Context(), m); err != nil {
				t.Fatal(err)
			}
			result := <-results
			if result.err != nil {
				t.Fatal(result.err)
			}
			commands := strings.Join(result.commands, "\n")
			if !strings.Contains(commands, "MAIL FROM:<sender@example.com>") || !strings.Contains(commands, "RCPT TO:<recipient@example.com>") {
				t.Fatal("incorrect SMTP envelope")
			}
			if mode == "starttls" && strings.Index(commands, "STARTTLS") > strings.Index(commands, "AUTH PLAIN") {
				t.Fatal("authentication preceded STARTTLS")
			}
			parsed, err := mail.ReadMessage(strings.NewReader(result.data))
			if err != nil {
				t.Fatal(err)
			}
			subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
			if err != nil || subject != m.Subject {
				t.Fatal("UTF-8 subject encoding")
			}
			if parsed.Header.Get("Reply-To") != "<reply@example.com>" || parsed.Header.Get("Message-ID") == "" || parsed.Header.Get("Date") == "" {
				t.Fatal("missing MIME headers")
			}
			media, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
			if err != nil || media != "multipart/alternative" {
				t.Fatal("missing multipart alternative")
			}
			multi := multipart.NewReader(parsed.Body, params["boundary"])
			for _, want := range []string{m.Text, m.HTML} {
				part, err := multi.NextPart()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(part)
				if err != nil || strings.ReplaceAll(string(data), "\r\n", "\n") != want {
					t.Fatalf("MIME body mismatch: %q", data)
				}
			}
			if _, err := multi.NextPart(); !errors.Is(err, io.EOF) {
				t.Fatal("extra MIME parts")
			}
		})
	}
}

func TestSMTPRejectsTLSFailuresBeforeCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, mode       string
		advertise, trust bool
	}{{"missing STARTTLS", "starttls", false, true}, {"untrusted implicit TLS", "tls", true, false}, {"untrusted STARTTLS", "starttls", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			host, port, roots, results := smtpPeer(t, tc.mode, tc.advertise)
			c := testConfig("smtp")
			c.SMTP.Host = host
			c.SMTP.Port = port
			c.SMTP.TLSMode = tc.mode
			if !tc.trust {
				roots = x509.NewCertPool()
			}
			s := &sender{config: c, transport: &smtpTransport{config: c, rootCAs: roots}}
			if err := s.Send(t.Context(), Message{To: "recipient@example.com", Subject: "test", Text: "body"}); err == nil {
				t.Fatal("insecure SMTP accepted")
			}
			result := <-results
			for _, command := range result.commands {
				if strings.HasPrefix(command, "AUTH") || strings.HasPrefix(command, "MAIL") || strings.HasPrefix(command, "RCPT") {
					t.Fatal("credentials or envelope sent before verified TLS")
				}
			}
		})
	}
}

func TestSMTPCancellationInterruptsGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	c := testConfig("smtp")
	c.SMTP.Host = host
	c.SMTP.Port = port
	s := &sender{config: c, transport: &smtpTransport{config: c}}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Send(ctx, Message{To: "recipient@example.com", Subject: "test", Text: "body"})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("SMTP did not honor cancellation: %v", err)
	}
	<-done
}

func TestMIMESingleBodies(t *testing.T) {
	for _, m := range []Message{{To: "a@example.com", Subject: "text", Text: "hello\n字"}, {To: "a@example.com", Subject: "html", HTML: "<p>字</p>"}} {
		data, err := encodeMIME(testConfig("smtp"), m)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := mail.ReadMessage(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
		if err != nil {
			t.Fatal(err)
		}
		want := m.Text
		if m.HTML != "" {
			want = m.HTML
		}
		if strings.ReplaceAll(string(body), "\r\n", "\n") != want {
			t.Fatal("single body encoding mismatch")
		}
	}
}
