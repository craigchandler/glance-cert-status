package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func configFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigDefaults(t *testing.T) {
	cfg, refresh, timeout, err := loadConfig(configFile(t, `{"targets":[{"name":"Example","url":"https://example.com"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Title != "Certificates" || cfg.ListenAddr != "127.0.0.1:8796" || refresh != 6*time.Hour || timeout != 10*time.Second || cfg.DefaultWarningDays != 30 || cfg.DefaultCriticalDays != 7 {
		t.Fatalf("unexpected defaults: %+v, %s, %s", cfg, refresh, timeout)
	}
	if cfg.Targets[0].WarningDays != 30 || cfg.Targets[0].CriticalDays != 7 || !targetEnabled(cfg.Targets[0]) {
		t.Fatalf("unexpected target defaults: %+v", cfg.Targets[0])
	}
}

func TestConfigOverrides(t *testing.T) {
	cfg, refresh, timeout, err := loadConfig(configFile(t, `{
		"title":"TLS", "listenAddr":"[::1]:9000", "refreshInterval":"1h", "connectTimeout":"2s",
		"defaultWarningDays":20, "defaultCriticalDays":4,
		"targets":[
			{"name":"Inherited","url":"https://example.com","enabled":true},
			{"name":"Override","url":"https://example.com","warningDays":12,"criticalDays":2,"enabled":false}
		]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Title != "TLS" || cfg.ListenAddr != "[::1]:9000" || refresh != time.Hour || timeout != 2*time.Second {
		t.Fatalf("overrides lost: %+v", cfg)
	}
	if cfg.Targets[0].WarningDays != 20 || cfg.Targets[0].CriticalDays != 4 || !targetEnabled(cfg.Targets[0]) || cfg.Targets[1].WarningDays != 12 || cfg.Targets[1].CriticalDays != 2 || targetEnabled(cfg.Targets[1]) {
		t.Fatalf("target overrides lost: %+v", cfg.Targets)
	}
}

func TestInvalidConfig(t *testing.T) {
	cases := []string{
		`null`, `[]`, `{`, `{} {}`, `{"refreshInterval":12}`,
		`{"refreshInterval":"invalid"}`, `{"refreshInterval":"0s"}`, `{"refreshInterval":"-1s"}`,
		`{"connectTimeout":"invalid"}`, `{"connectTimeout":"0s"}`, `{"connectTimeout":"-1s"}`,
		`{"defaultWarningDays":7}`, `{"defaultCriticalDays":30}`, `{"defaultCriticalDays":31}`,
		`{"defaultWarningDays":-1}`, `{"defaultCriticalDays":-1}`,
		`{"targets":[{"url":"https://example.com"}]}`,
		`{"targets":[{"name":"Example"}]}`,
		`{"targets":[{"name":"Example","url":"http://example.com"}]}`,
		`{"targets":[{"name":"Example","url":"https://example.com:65536"}]}`,
		`{"targets":[{"name":"Example","url":"https://example.com","warningDays":7}]}`,
		`{"targets":[{"name":"Example","url":"https://example.com","criticalDays":31}]}`,
		`{"targets":[{"name":"Example","url":"https://example.com","criticalDays":-1}]}`,
		`{"targets":[{"name":"Example","url":"https://example.com","warningDays":-1}]}`,
		`{"targets":[{"name":"Example","url":"bad","enabled":false}]}`,
	}
	for _, contents := range cases {
		t.Run(contents, func(t *testing.T) {
			if _, _, _, err := loadConfig(configFile(t, contents)); err == nil {
				t.Fatal("expected startup validation error")
			}
		})
	}
	if _, _, _, err := loadConfig(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing config accepted")
	}
}

func TestTargetAddress(t *testing.T) {
	for _, tc := range []struct{ url, override, host, port, serverName string }{
		{"https://example.com", "", "example.com", "443", "example.com"},
		{"HTTPS://example.com:8443/path?q=ignored#fragment", "", "example.com", "8443", "example.com"},
		{"https://127.0.0.1:9443", " example.com ", "127.0.0.1", "9443", "example.com"},
		{"https://127.0.0.1", "", "127.0.0.1", "443", "127.0.0.1"},
		{"https://[::1]", "", "::1", "443", "::1"},
		{"https://[2001:db8::1]:8443", "example.com", "2001:db8::1", "8443", "example.com"},
		{"https://[fe80::1%25eth0]:8443", "", "fe80::1%eth0", "8443", "fe80::1"},
		{"https://example.com.", "", "example.com.", "443", "example.com."},
	} {
		t.Run(tc.url, func(t *testing.T) {
			host, port, name, err := targetAddress(Target{URL: tc.url, ServerName: tc.override})
			if err != nil || host != tc.host || port != tc.port || name != tc.serverName {
				t.Fatalf("got %q %q %q %v", host, port, name, err)
			}
		})
	}
}

func TestInvalidTargetAddress(t *testing.T) {
	for _, value := range []string{
		"", "example.com", "http://example.com", "tls://example.com", "https:example.com", "https:///path",
		"https://", "https://:443", "https://example.com:", "https://example.com:0", "https://example.com:65536",
		"https://example.com:-1", "https://example.com:abc", "https://::1", "https://2001:db8::1:443",
		"https://[example.com]", "https://[127.0.0.1]", "https://[::1", "https://exa mple.com", "https://example.com/%zz",
		"https://user:dummy-password@example.com", "https://example..com", "https://-example.com", "https://example.com\n",
	} {
		t.Run(value, func(t *testing.T) {
			if _, _, _, err := targetAddress(Target{URL: value}); err == nil {
				t.Fatal("invalid URL accepted")
			} else if strings.Contains(err.Error(), "dummy-password") {
				t.Fatal("credentials echoed in validation error")
			}
		})
	}
	for _, name := range []string{"example.com:443", "https://example.com", "*.example.com", "[::1]", "fe80::1%eth0", "bad name"} {
		if _, _, _, err := targetAddress(Target{URL: "https://example.com", ServerName: name}); err == nil {
			t.Errorf("invalid serverName %q accepted", name)
		}
	}
}

// Generate only ephemeral test keys; nothing is added to the system trust store.
func issueCertificate(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestInspectCertificate(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root, rootKey := issueCertificate(t, caTemplate, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediate, intermediateKey := issueCertificate(t, caTemplate, root, rootKey)
	for _, tc := range []struct {
		name, serverName, status, message                                       string
		days                                                                    int
		future, untrusted, missingIntermediate, wrongUsage, rootFailure, noPeer bool
	}{
		{name: "healthy", days: 60, status: "healthy", message: "expires in 60 days"},
		{name: "warning boundary", days: 30, status: "warning", message: "expires in 30 days"},
		{name: "critical boundary", days: 7, status: "critical", message: "expires in 7 days"},
		{name: "just above critical", days: 8, status: "warning", message: "expires in 8 days"},
		{name: "just above warning", days: 31, status: "healthy", message: "expires in 31 days"},
		{name: "expired", days: -1, status: "critical", message: "certificate has expired"},
		{name: "expiry instant", days: 0, status: "critical", message: "certificate has expired"},
		{name: "future", days: 60, future: true, status: "critical", message: "certificate is not valid yet"},
		{name: "hostname mismatch", days: 60, serverName: "other.example.com", status: "critical", message: "certificate does not match other.example.com"},
		{name: "IP SAN", days: 60, serverName: "127.0.0.1", status: "healthy", message: "expires in 60 days"},
		{name: "untrusted", days: 60, untrusted: true, status: "critical", message: "certificate chain is not trusted"},
		{name: "missing intermediate", days: 60, missingIntermediate: true, status: "critical", message: "certificate chain is not trusted"},
		{name: "wrong usage", days: 60, wrongUsage: true, status: "critical", message: "certificate chain is not trusted"},
		{name: "trust store failure", days: 60, rootFailure: true, status: "critical", message: "could not load system trust store: test error"},
		{name: "no peer certificate", noPeer: true, status: "critical", message: "server returned no certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
				NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(time.Duration(tc.days) * 24 * time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if tc.future {
				leafTemplate.NotBefore = now.Add(time.Hour)
			}
			if tc.wrongUsage {
				leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			leaf, _ := issueCertificate(t, leafTemplate, intermediate, intermediateKey)
			peer := []*x509.Certificate{leaf, intermediate}
			if tc.missingIntermediate {
				peer = peer[:1]
			}
			if tc.noPeer {
				peer = nil
			}
			pool := roots
			if tc.untrusted {
				pool = x509.NewCertPool()
			}
			var rootErr error
			if tc.rootFailure {
				pool, rootErr = nil, errors.New("test error")
			}
			name := tc.serverName
			if name == "" {
				name = "example.com"
			}
			got := inspectCertificate(CertificateStatus{Status: "critical", ServerName: name, CheckedAt: now, WarningDays: 30, CriticalDays: 7}, peer, pool, rootErr)
			if got.Status != tc.status || got.Message != tc.message {
				t.Fatalf("got %s: %s; want %s: %s", got.Status, got.Message, tc.status, tc.message)
			}
			if !tc.noPeer && (got.SerialNumber != "2" || !got.NotAfter.Equal(leaf.NotAfter) || got.DaysRemaining != tc.days || got.HostnameValid != (tc.serverName != "other.example.com")) {
				t.Fatalf("incorrect certificate metadata: %+v", got)
			}
			wantChain := !tc.noPeer && !tc.untrusted && !tc.missingIntermediate && !tc.wrongUsage && !tc.rootFailure && !tc.future && tc.days >= 0 && tc.serverName != "other.example.com"
			if got.ChainValid != wantChain {
				t.Fatalf("chainValid = %v, want %v", got.ChainValid, wantChain)
			}
		})
	}
}

func TestTLSInspectionAndRefresh(t *testing.T) {
	now := time.Now()
	cert, key := issueCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), DNSNames: []string{"example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, nil, nil)
	var requests atomic.Int32
	sni := make(chan string, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil },
	}
	server.StartTLS()
	defer server.Close()
	target := Target{Name: "Example", URL: server.URL + "/never-fetched", ServerName: "example.com", WarningDays: 30, CriticalDays: 7}
	got := checkCertificate(target, time.Second, now)
	if got.Status != "critical" || !got.HostnameValid || got.ChainValid || got.SerialNumber != "3" || got.Message != "certificate chain is not trusted" {
		t.Fatalf("self-signed certificate was not inspected correctly: %+v", got)
	}
	if name := <-sni; name != "example.com" {
		t.Fatalf("SNI = %q", name)
	}
	for _, tc := range []struct {
		offset  time.Duration
		message string
	}{
		{-2 * time.Hour, "certificate is not valid yet"},
		{61 * 24 * time.Hour, "certificate has expired"},
	} {
		got := checkCertificate(target, time.Second, now.Add(tc.offset))
		if got.Message != tc.message || got.SerialNumber != "3" {
			t.Fatalf("invalid dates prevented inspection: %+v", got)
		}
	}
	mismatch := target
	mismatch.ServerName = "other.example.com"
	if got := checkCertificate(mismatch, time.Second, now); got.HostnameValid || got.Message != "certificate does not match other.example.com" {
		t.Fatalf("mismatch: %+v", got)
	}
	disabled := false
	app := &App{cfg: Config{Targets: []Target{target, {Name: "Disabled", URL: "invalid", Enabled: &disabled}}}, timeout: time.Second}
	app.refresh()
	st := app.get()
	if len(st.Certificates) != 1 || len(st.Attention) != 1 || st.CriticalCount != 1 || st.HealthyCount != 0 || st.WarningCount != 0 {
		t.Fatalf("refresh: %+v", st)
	}
	if requests.Load() != 0 {
		t.Fatal("inspection sent an HTTP request")
	}
}

func TestTLSMinimumVersion(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	server.StartTLS()
	defer server.Close()
	got := checkCertificate(Target{URL: server.URL}, time.Second, time.Now())
	if got.Status != "critical" || !strings.HasPrefix(got.Message, "TLS connection failed:") {
		t.Fatalf("legacy TLS accepted: %+v", got)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			<-done
		}
	}()
	start := time.Now()
	got := checkCertificate(Target{URL: "https://" + listener.Addr().String()}, 100*time.Millisecond, start)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("handshake timeout took %s", elapsed)
	}
	if got.Status != "critical" || !(strings.Contains(got.Message, "timeout") || strings.Contains(got.Message, "deadline exceeded")) {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestHTTPRoutes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state State
		code  int
	}{
		{"healthy", State{HealthyCount: 2}, http.StatusOK},
		{"warning", State{WarningCount: 1}, http.StatusOK},
		{"critical", State{CriticalCount: 1}, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &App{state: tc.state}
			w := httptest.NewRecorder()
			app.routes().ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
			var payload struct {
				OK       bool `json:"ok"`
				Critical int  `json:"criticalCount"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.code || payload.OK != (tc.code == http.StatusOK) || payload.Critical != tc.state.CriticalCount {
				t.Fatalf("health: %d %s", w.Code, w.Body)
			}
		})
	}
	app := &App{}
	app.refresh()
	for _, tc := range []struct {
		path string
		code int
	}{{"/status", 200}, {"/widget", 200}, {"/", 307}, {"/unknown", 404}} {
		w := httptest.NewRecorder()
		app.routes().ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		if w.Code != tc.code {
			t.Errorf("%s: %d", tc.path, w.Code)
		}
		if tc.path == "/status" && (!strings.Contains(w.Body.String(), `"attention":[]`) || !strings.Contains(w.Body.String(), `"certificates":[]`)) {
			t.Fatalf("empty collections are not arrays: %s", w.Body)
		}
		if tc.path == "/" && w.Header().Get("Location") != "/widget" {
			t.Fatal("incorrect redirect")
		}
	}
}

func TestWidgetEscapesCertificateData(t *testing.T) {
	payload := `<script>alert("test")</script>`
	app := &App{cfg: Config{Title: "Certificates"}, state: State{CriticalCount: 1, Certificates: []CertificateStatus{{
		Name: payload, ServerName: payload, Issuer: payload, Message: payload, Status: "critical",
	}}}}
	w := httptest.NewRecorder()
	app.widget(w, httptest.NewRequest("GET", "/widget", nil))
	if strings.Contains(w.Body.String(), "<script>") || strings.Count(w.Body.String(), "&lt;script&gt;") != 4 {
		t.Fatalf("unsafe or missing output: %s", w.Body)
	}
	if w.Header().Get("Widget-Title") != "Certificates" || w.Header().Get("Widget-Content-Type") != "html" || !strings.Contains(w.Body.String(), "color-negative") {
		t.Fatal("widget headers or severity missing")
	}
}

func TestRefreshLimitsConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, maxConcurrentChecks+2)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	app := &App{timeout: 5 * time.Second}
	for i := 0; i < maxConcurrentChecks+2; i++ {
		app.cfg.Targets = append(app.cfg.Targets, Target{URL: "https://" + listener.Addr().String()})
	}
	done := make(chan struct{})
	go func() { app.refresh(); close(done) }()
	var held []net.Conn
	for i := 0; i < maxConcurrentChecks; i++ {
		select {
		case conn := <-accepted:
			held = append(held, conn)
			defer conn.Close()
		case <-time.After(3 * time.Second):
			t.Fatal("initial checks did not connect")
		}
	}
	select {
	case conn := <-accepted:
		conn.Close()
		t.Fatal("concurrent check limit exceeded")
	case <-time.After(100 * time.Millisecond):
	}
	for _, conn := range held {
		conn.Close()
	}
	for i := 0; i < 2; i++ {
		select {
		case conn := <-accepted:
			conn.Close()
		case <-time.After(3 * time.Second):
			t.Fatal("queued checks did not run")
		}
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("failed endpoints stalled refresh")
	}
	if got := app.get(); got.CriticalCount != maxConcurrentChecks+2 || len(got.Attention) != maxConcurrentChecks+2 {
		t.Fatalf("failed endpoints missing: %+v", got)
	}
}

func TestConcurrentStateAccess(t *testing.T) {
	app := &App{cfg: Config{Targets: []Target{{Name: "Invalid", URL: "invalid"}}}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			app.refresh()
		}
	}()
	for i := 0; i < 100; i++ {
		for _, path := range []string{"/health", "/status", "/widget"} {
			app.routes().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
		}
	}
	<-done
}
