package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var version = "dev"

type Target struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	ServerName   string `json:"serverName,omitempty"`
	WarningDays  int    `json:"warningDays,omitempty"`
	CriticalDays int    `json:"criticalDays,omitempty"`
	Enabled      *bool  `json:"enabled,omitempty"`
}

type Config struct {
	Title               string   `json:"title"`
	ListenAddr          string   `json:"listenAddr"`
	RefreshInterval     string   `json:"refreshInterval"`
	ConnectTimeout      string   `json:"connectTimeout"`
	DefaultWarningDays  int      `json:"defaultWarningDays"`
	DefaultCriticalDays int      `json:"defaultCriticalDays"`
	Targets             []Target `json:"targets"`
}

type CertificateStatus struct {
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Host          string    `json:"host"`
	ServerName    string    `json:"serverName"`
	Status        string    `json:"status"`
	Message       string    `json:"message,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	SerialNumber  string    `json:"serialNumber,omitempty"`
	NotBefore     time.Time `json:"notBefore,omitempty"`
	NotAfter      time.Time `json:"notAfter,omitempty"`
	DaysRemaining int       `json:"daysRemaining"`
	HostnameValid bool      `json:"hostnameValid"`
	ChainValid    bool      `json:"chainValid"`
	WarningDays   int       `json:"warningDays"`
	CriticalDays  int       `json:"criticalDays"`
	CheckedAt     time.Time `json:"checkedAt"`
}

type AttentionItem struct {
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Status        string    `json:"status"`
	Message       string    `json:"message"`
	DaysRemaining int       `json:"daysRemaining"`
	NotAfter      time.Time `json:"notAfter,omitempty"`
}

type State struct {
	Certificates  []CertificateStatus `json:"certificates"`
	Attention     []AttentionItem     `json:"attention"`
	HealthyCount  int                 `json:"healthyCount"`
	WarningCount  int                 `json:"warningCount"`
	CriticalCount int                 `json:"criticalCount"`
	RefreshedAt   time.Time           `json:"refreshedAt"`
}

type App struct {
	mu      sync.RWMutex
	cfg     Config
	state   State
	timeout time.Duration
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-version", "version":
			fmt.Println(version)
			return
		}
	}

	cfg, refresh, timeout, err := loadConfig(env("CONFIG_FILE", "/etc/cert-status.json"))
	if err != nil {
		log.Fatal(err)
	}

	app := &App{cfg: cfg, timeout: timeout}
	app.refresh()

	go func() {
		ticker := time.NewTicker(refresh)
		defer ticker.Stop()
		for range ticker.C {
			app.refresh()
		}
	}()

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	log.Printf("cert-status %s listening on http://%s", version, cfg.ListenAddr)
	log.Printf("monitoring %d configured certificate target(s), refresh=%s", len(cfg.Targets), refresh)
	log.Fatal(server.ListenAndServe())
}

func (app *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.health)
	mux.HandleFunc("/status", app.status)
	mux.HandleFunc("/widget", app.widget)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/widget", http.StatusTemporaryRedirect)
	})

	return mux
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func loadConfig(path string) (Config, time.Duration, time.Duration, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, 0, 0, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := Config{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, 0, 0, fmt.Errorf("parse config %s: %w", path, err)
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return Config{}, 0, 0, errors.New("config must be a JSON object")
	}

	if cfg.Title == "" {
		cfg.Title = "Certificates"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:8796"
	}
	if cfg.RefreshInterval == "" {
		cfg.RefreshInterval = "6h"
	}
	if cfg.ConnectTimeout == "" {
		cfg.ConnectTimeout = "10s"
	}
	if cfg.DefaultWarningDays < 0 || cfg.DefaultCriticalDays < 0 {
		return Config{}, 0, 0, errors.New("default expiry thresholds must not be negative")
	}
	if cfg.DefaultWarningDays == 0 {
		cfg.DefaultWarningDays = 30
	}
	if cfg.DefaultCriticalDays == 0 {
		cfg.DefaultCriticalDays = 7
	}
	if cfg.DefaultCriticalDays >= cfg.DefaultWarningDays {
		return Config{}, 0, 0, errors.New("defaultCriticalDays must be less than defaultWarningDays")
	}

	refresh, err := time.ParseDuration(cfg.RefreshInterval)
	if err != nil || refresh <= 0 {
		return Config{}, 0, 0, fmt.Errorf("invalid refreshInterval %q", cfg.RefreshInterval)
	}
	timeout, err := time.ParseDuration(cfg.ConnectTimeout)
	if err != nil || timeout <= 0 {
		return Config{}, 0, 0, fmt.Errorf("invalid connectTimeout %q", cfg.ConnectTimeout)
	}

	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if strings.TrimSpace(t.Name) == "" {
			return Config{}, 0, 0, fmt.Errorf("targets[%d].name is required", i)
		}
		if strings.TrimSpace(t.URL) == "" {
			return Config{}, 0, 0, fmt.Errorf("targets[%d].url is required", i)
		}
		if t.WarningDays < 0 || t.CriticalDays < 0 {
			return Config{}, 0, 0, fmt.Errorf("targets[%d]: expiry thresholds must not be negative", i)
		}
		if t.WarningDays == 0 {
			t.WarningDays = cfg.DefaultWarningDays
		}
		if t.CriticalDays == 0 {
			t.CriticalDays = cfg.DefaultCriticalDays
		}
		if t.CriticalDays >= t.WarningDays {
			return Config{}, 0, 0, fmt.Errorf("targets[%d]: criticalDays must be less than warningDays", i)
		}
		if _, _, _, err := targetAddress(*t); err != nil {
			return Config{}, 0, 0, fmt.Errorf("targets[%d]: %w", i, err)
		}
	}

	return cfg, refresh, timeout, nil
}

func targetEnabled(t Target) bool {
	return t.Enabled == nil || *t.Enabled
}

func targetAddress(t Target) (host, port, serverName string, err error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		// Do not echo a malformed URL: it may contain accidental credentials.
		return "", "", "", errors.New("invalid target URL")
	}
	if u.User != nil {
		return "", "", "", errors.New("target URL must not contain user information")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", "", "", errors.New("target URL must use https")
	}
	if !validHost(u.Hostname()) {
		return "", "", "", errors.New("target URL must have a valid hostname or IP address")
	}

	host = u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() {
			return "", "", "", errors.New("URL brackets require an IPv6 address")
		}
	} else if strings.Contains(host, ":") {
		return "", "", "", errors.New("IPv6 URL addresses must be enclosed in brackets")
	}
	port = u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", "", "", errors.New("target URL has an empty port")
	}
	if port == "" {
		port = "443"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", "", errors.New("target port must be between 1 and 65535")
	}
	serverName = strings.TrimSpace(t.ServerName)
	if serverName == "" {
		serverName = host
		// The interface zone is for dialing only, never certificate identity.
		if ip, err := netip.ParseAddr(host); err == nil {
			serverName = ip.WithZone("").String()
		}
	}
	if !validHost(serverName) || strings.Contains(serverName, "%") {
		return "", "", "", errors.New("serverName must be a DNS name or IP address without a port or zone")
	}
	return host, port, serverName, nil
}

func validHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

const maxConcurrentChecks = 8

func (a *App) refresh() {
	now := time.Now()
	var wg sync.WaitGroup
	ch := make(chan CertificateStatus, len(a.cfg.Targets))
	slots := make(chan struct{}, maxConcurrentChecks)

	for _, target := range a.cfg.Targets {
		if !targetEnabled(target) {
			continue
		}
		target := target
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			ch <- checkCertificate(target, a.timeout, time.Now())
		}()
	}

	wg.Wait()
	close(ch)

	st := State{RefreshedAt: now, Certificates: []CertificateStatus{}, Attention: []AttentionItem{}}
	for cert := range ch {
		st.Certificates = append(st.Certificates, cert)
		switch cert.Status {
		case "critical":
			st.CriticalCount++
			st.Attention = append(st.Attention, AttentionItem{
				Name: cert.Name, URL: cert.URL, Status: cert.Status, Message: cert.Message,
				DaysRemaining: cert.DaysRemaining, NotAfter: cert.NotAfter,
			})
		case "warning":
			st.WarningCount++
			st.Attention = append(st.Attention, AttentionItem{
				Name: cert.Name, URL: cert.URL, Status: cert.Status, Message: cert.Message,
				DaysRemaining: cert.DaysRemaining, NotAfter: cert.NotAfter,
			})
		default:
			st.HealthyCount++
		}
	}

	sort.SliceStable(st.Attention, func(i, j int) bool {
		rank := func(v string) int {
			if v == "critical" {
				return 0
			}
			return 1
		}
		ri, rj := rank(st.Attention[i].Status), rank(st.Attention[j].Status)
		if ri != rj {
			return ri < rj
		}
		return st.Attention[i].DaysRemaining < st.Attention[j].DaysRemaining
	})

	sort.SliceStable(st.Certificates, func(i, j int) bool {
		rank := func(v string) int {
			switch v {
			case "critical":
				return 0
			case "warning":
				return 1
			default:
				return 2
			}
		}
		ri, rj := rank(st.Certificates[i].Status), rank(st.Certificates[j].Status)
		if ri != rj {
			return ri < rj
		}
		return st.Certificates[i].DaysRemaining < st.Certificates[j].DaysRemaining
	})

	a.mu.Lock()
	a.state = st
	a.mu.Unlock()
}

func checkCertificate(t Target, timeout time.Duration, now time.Time) CertificateStatus {
	host, port, serverName, err := targetAddress(t)
	result := CertificateStatus{
		Name:          t.Name,
		URL:           t.URL,
		Host:          host,
		ServerName:    serverName,
		Status:        "critical",
		WarningDays:   t.WarningDays,
		CriticalDays:  t.CriticalDays,
		CheckedAt:     now,
		DaysRemaining: -1,
	}
	if err != nil {
		result.Message = err.Error()
		return result
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName: serverName,
		// Inspection only: inspectCertificate explicitly verifies dates, hostname
		// and trust. No application data or credentials are sent on this connection.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		result.Message = fmt.Sprintf("TLS connection failed: %v", err)
		return result
	}
	defer conn.Close()

	roots, rootErr := x509.SystemCertPool()
	return inspectCertificate(result, conn.ConnectionState().PeerCertificates, roots, rootErr)
}

// Kept separate from dialing so verification can be tested with isolated roots.
// Production always supplies the system trust store, never peer trust anchors.
func inspectCertificate(result CertificateStatus, peer []*x509.Certificate, roots *x509.CertPool, rootErr error) CertificateStatus {
	now, serverName := result.CheckedAt, result.ServerName
	if len(peer) == 0 {
		result.Message = "server returned no certificate"
		return result
	}

	cert := peer[0]
	result.Subject = cert.Subject.String()
	result.Issuer = cert.Issuer.String()
	result.SerialNumber = cert.SerialNumber.String()
	result.NotBefore = cert.NotBefore
	result.NotAfter = cert.NotAfter
	result.HostnameValid = cert.VerifyHostname(serverName) == nil
	result.DaysRemaining = int(cert.NotAfter.Sub(now).Hours() / 24)

	if rootErr == nil {
		intermediates := x509.NewCertPool()
		for _, intermediate := range peer[1:] {
			intermediates.AddCert(intermediate)
		}
		_, verifyErr := cert.Verify(x509.VerifyOptions{
			DNSName:       serverName,
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   now,
		})
		result.ChainValid = verifyErr == nil
	}

	if now.Before(cert.NotBefore) {
		result.Status = "critical"
		result.Message = "certificate is not valid yet"
		return result
	}
	if !result.HostnameValid {
		result.Status = "critical"
		result.Message = fmt.Sprintf("certificate does not match %s", serverName)
		return result
	}
	if !now.Before(cert.NotAfter) {
		result.Status = "critical"
		result.Message = "certificate has expired"
		return result
	}
	if rootErr != nil {
		result.Status = "critical"
		result.Message = fmt.Sprintf("could not load system trust store: %v", rootErr)
		return result
	}
	if !result.ChainValid {
		result.Status = "critical"
		result.Message = "certificate chain is not trusted"
		return result
	}
	if result.DaysRemaining <= result.CriticalDays {
		result.Status = "critical"
		result.Message = fmt.Sprintf("expires in %d days", result.DaysRemaining)
		return result
	}
	if result.DaysRemaining <= result.WarningDays {
		result.Status = "warning"
		result.Message = fmt.Sprintf("expires in %d days", result.DaysRemaining)
		return result
	}

	result.Status = "healthy"
	result.Message = fmt.Sprintf("expires in %d days", result.DaysRemaining)
	return result
}

func (a *App) get() State {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	st := a.get()
	w.Header().Set("Content-Type", "application/json")
	if st.CriticalCount > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":            st.CriticalCount == 0,
		"healthyCount":  st.HealthyCount,
		"warningCount":  st.WarningCount,
		"criticalCount": st.CriticalCount,
		"refreshedAt":   st.RefreshedAt,
	})
}

func (a *App) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.get())
}

var wt = template.Must(template.New("widget").Funcs(template.FuncMap{
	"class": func(status string) string {
		switch status {
		case "critical":
			return "color-negative"
		case "warning":
			return "color-highlight"
		default:
			return "color-positive"
		}
	},
	"label": strings.ToUpper,
	"date":  func(t time.Time) string { return t.Local().Format("2 Jan 2006") },
	"days": func(v int) string {
		if v < 0 {
			return "-"
		}
		if v == 1 {
			return "1 day"
		}
		return strconv.Itoa(v) + " days"
	},
}).Parse(`<div class="widget-content">
{{if not .State.Certificates}}
  <div class="color-paragraph">No certificate targets configured.</div>
{{else}}
  <div class="flex justify-between">
    <span>{{len .State.Certificates}} certificates</span>
    {{if gt .State.CriticalCount 0}}<strong class="color-negative">{{.State.CriticalCount}} CRITICAL</strong>{{else if gt .State.WarningCount 0}}<strong class="color-highlight">{{.State.WarningCount}} WARNING</strong>{{else}}<strong class="color-positive">ALL GOOD</strong>{{end}}
  </div>
  {{range .State.Certificates}}
    <details class="details margin-top-10" {{if ne .Status "healthy"}}open{{end}}>
      <summary class="summary">
        <div class="flex justify-between gap-10">
          <strong>{{.Name}}</strong>
          <span class="{{class .Status}}">{{if eq .Status "healthy"}}{{days .DaysRemaining}}{{else}}{{label .Status}}{{end}}</span>
        </div>
      </summary>
      <div class="margin-top-10">
        <div class="flex justify-between"><span>Host</span><span>{{.ServerName}}</span></div>
        {{if not .NotAfter.IsZero}}<div class="flex justify-between"><span>Expires</span><span>{{date .NotAfter}}</span></div>{{end}}
        <div class="flex justify-between"><span>Remaining</span><span class="{{class .Status}}">{{days .DaysRemaining}}</span></div>
        {{if .Issuer}}<div class="color-paragraph size-h6 margin-top-5">Issuer: {{.Issuer}}</div>{{end}}
        {{if .Message}}<div class="color-paragraph size-h6 margin-top-5">{{.Message}}</div>{{end}}
      </div>
    </details>
  {{end}}
{{end}}
</div>`))

func (a *App) widget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Widget-Title", a.cfg.Title)
	w.Header().Set("Widget-Content-Type", "html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = wt.Execute(w, map[string]any{"State": a.get()})
}
