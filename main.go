package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

type Result struct {
	URL          string            `json:"url"`
	Reachable    bool              `json:"reachable"`
	StatusCode   int               `json:"status_code,omitempty"`
	Err          string            `json:"err,omitempty"`
	DurationMS   int64             `json:"duration_ms"`
	Bytes        int               `json:"bytes,omitempty"`
	HTMLPath     string            `json:"html_path,omitempty"`
	Screenshot   string            `json:"screenshot_path,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	TimestampUTC string            `json:"timestamp_utc"`
}

func main() {
	var (
		targetsPath = flag.String("targets", "targets.yaml", "Path to targets file (one URL per line; YAML list '- url' also accepted)")
		outRoot     = flag.String("out", "out", "Output root directory")
		proxyAddr   = flag.String("proxy", "127.0.0.1:9050", "Tor SOCKS5 address (9050 for Tor service, 9150 often for Tor Browser)")
		timeoutStr  = flag.String("timeout", "60s", "Per-request timeout (e.g., 30s, 60s, 2m)")
		concurrency = flag.Int("concurrency", 3, "Number of concurrent workers (Tor is slow; keep small)")
		screenshot  = flag.Bool("screenshot", true, "Try to capture a screenshot using headless Chrome/Chromium")
		chromePath  = flag.String("chrome", "", "Optional path to chrome/chromium executable. If empty, auto-detect common paths.")
		insecureTLS = flag.Bool("insecure", true, "Skip TLS certificate verification (helps with self-signed/invalid TLS)")
		maxBytes    = flag.Int("max-bytes", 3*1024*1024, "Max HTML bytes to store per URL (safety cap)")
	)
	flag.Parse()

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] invalid -timeout: %v\n", err)
		os.Exit(2)
	}

	// Create run folder
	runID := time.Now().Format("20060102_150405")
	runDir := filepath.Join(*outRoot, "run_"+runID)
	htmlDir := filepath.Join(runDir, "html")
	shotDir := filepath.Join(runDir, "screenshots")
	if err := os.MkdirAll(htmlDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] mkdir: %v\n", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(shotDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] mkdir: %v\n", err)
		os.Exit(2)
	}

	logPath := filepath.Join(runDir, "scan_report.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] open log: %v\n", err)
		os.Exit(2)
	}
	defer logFile.Close()
	logger := io.MultiWriter(os.Stdout, logFile)

	jsonlPath := filepath.Join(runDir, "scan_report.jsonl")
	jsonlFile, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] open jsonl: %v\n", err)
		os.Exit(2)
	}
	defer jsonlFile.Close()
	jsonlMu := &sync.Mutex{} // serialize JSONL writes

	writeLog(logger, "[INFO] Tor Scraper started. out=%s proxy=%s timeout=%s concurrency=%d screenshot=%v", runDir, *proxyAddr, timeout, *concurrency, *screenshot)

	// Build Tor HTTP client (SOCKS5 only; prevents IP leaks by not using default dialer/proxy env).
	client, err := newTorHTTPClient(*proxyAddr, timeout, *insecureTLS)
	if err != nil {
		writeLog(logger, "[FATAL] cannot build Tor client: %v", err)
		os.Exit(2)
	}

	// Tor IP verification (recommended by assignment)
	if ip, isTor, err := checkTorIP(client); err != nil {
		writeLog(logger, "[WARN] Tor IP check failed: %v", err)
	} else {
		writeLog(logger, "[INFO] Tor IP check: ip=%s is_tor=%v (via check.torproject.org/api/ip)", ip, isTor)
	}

	// Read targets
	targets, err := readTargets(*targetsPath)
	if err != nil {
		writeLog(logger, "[FATAL] read targets: %v", err)
		os.Exit(2)
	}
	if len(targets) == 0 {
		writeLog(logger, "[FATAL] no targets found in %s", *targetsPath)
		os.Exit(2)
	}
	writeLog(logger, "[INFO] Loaded %d unique targets from %s", len(targets), *targetsPath)

	// Screenshot engine (optional)
	chromeExe := ""
	if *screenshot {
		chromeExe = *chromePath
		if chromeExe == "" {
			chromeExe = autoDetectChrome()
		}
		if chromeExe == "" {
			writeLog(logger, "[WARN] screenshot enabled but Chrome/Chromium not found. Run with -screenshot=false or provide -chrome=PATH")
		} else {
			writeLog(logger, "[INFO] screenshot engine: %s", chromeExe)
		}
	}

	// Worker pool
	jobs := make(chan string)
	var okCount int64
	var failCount int64

	var wg sync.WaitGroup
	worker := func(id int) {
		defer wg.Done()
		for target := range jobs {
			start := time.Now()
			writeLog(logger, "[INFO] Scanning: %s", target)

			res := Result{
				URL:          target,
				TimestampUTC: time.Now().UTC().Format(time.RFC3339),
			}

			// Fetch HTML
			status, body, headers, err := fetchHTML(client, target, timeout, *maxBytes)
			res.DurationMS = time.Since(start).Milliseconds()

			if err != nil {
				res.Reachable = false
				res.Err = err.Error()
				atomic.AddInt64(&failCount, 1)
				writeLog(logger, "[ERR]  Scanning: %s -> FAIL (%s)", target, res.Err)
				writeJSONL(jsonlFile, jsonlMu, res)
				continue
			}

			res.Reachable = true
			res.StatusCode = status
			res.Bytes = len(body)
			res.Headers = headers

			// Save HTML
			htmlName := safeName(target) + ".html"
			htmlPath := filepath.Join(htmlDir, htmlName)
			if werr := os.WriteFile(htmlPath, body, 0o644); werr != nil {
				// still count as reachable, but log error
				res.Err = "html_write: " + werr.Error()
				writeLog(logger, "[WARN] HTML write failed for %s: %v", target, werr)
			} else {
				res.HTMLPath = filepath.Base(htmlPath)
			}

			// Screenshot (best-effort)
			if *screenshot && chromeExe != "" {
				shotName := safeName(target) + ".png"
				shotPath := filepath.Join(shotDir, shotName)

				sctx, cancel := context.WithTimeout(context.Background(), timeout+30*time.Second)
				serr := takeScreenshotChrome(sctx, chromeExe, target, shotPath, *proxyAddr)
				cancel()

				if serr != nil {
					writeLog(logger, "[WARN] Screenshot failed for %s: %v", target, serr)
				} else {
					res.Screenshot = filepath.Base(shotPath)
				}
			}

			atomic.AddInt64(&okCount, 1)
			writeLog(logger, "[INFO] Done: %s -> SUCCESS (status=%d bytes=%d dur=%dms)", target, res.StatusCode, res.Bytes, res.DurationMS)

			writeJSONL(jsonlFile, jsonlMu, res)
		}
	}

	if *concurrency < 1 {
		*concurrency = 1
	}
	wg.Add(*concurrency)
	for i := 0; i < *concurrency; i++ {
		go worker(i + 1)
	}

	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()

	writeLog(logger, "[INFO] Finished. success=%d fail=%d. Outputs: %s", okCount, failCount, runDir)
	writeLog(logger, "[INFO] Report files: %s , %s", logPath, jsonlPath)
}

// ----------------------------- Input --------------------------------

var onionURLRegex = regexp.MustCompile(`https?://[^\s"']+?\.onion[^\s"']*`)

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string

	sc := bufio.NewScanner(f)
	// Allow long lines (some URLs are long)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// allow comments
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Allow YAML list syntax: "- http://...onion"
		line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
		line = strings.TrimSpace(strings.Trim(line, `"'`))

		// If a line contains "Site Linki: <url>" etc, extract from it
		if strings.Contains(line, ".onion") {
			matches := onionURLRegex.FindAllString(line, -1)
			if len(matches) == 0 {
				// fallback: if line itself is URL-ish
				matches = []string{line}
			}
			for _, m := range matches {
				u := strings.TrimSpace(strings.Trim(m, `"'`))
				// Basic normalization
				if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
					u = "http://" + u
				}
				if _, err := url.Parse(u); err != nil {
					continue
				}
				if !seen[u] {
					seen[u] = true
					out = append(out, u)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// ----------------------------- Tor client ----------------------------

func newTorHTTPClient(socksAddr string, timeout time.Duration, insecureTLS bool) (*http.Client, error) {
	// SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	// Wrap into a net.Dial function (http.Transport expects this signature).
	dialFunc := func(network, addr string) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}

	tr := &http.Transport{
		Proxy:                 nil, // DO NOT use env proxies (prevents leaks)
		Dial:                  dialFunc,
		ForceAttemptHTTP2:     false,
		DisableCompression:    false,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureTLS, // best effort for onion/self-signed TLS
		},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Limit redirects to avoid loops
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	return client, nil
}

func fetchHTML(client *http.Client, target string, timeout time.Duration, maxBytes int) (int, []byte, map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, nil, err
	}

	// Basic headers to behave like a browser (some onion sites block empty UA)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; TorScraper/1.0; +CTI)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, classifyNetErr(err)
	}
	defer resp.Body.Close()

	// Read with cap
	limited := io.LimitReader(resp.Body, int64(maxBytes))
	body, err := io.ReadAll(limited)
	if err != nil {
		return resp.StatusCode, nil, nil, err
	}

	headers := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return resp.StatusCode, body, headers, nil
}

func classifyNetErr(err error) error {
	// Normalize common errors for easier reporting
	msg := err.Error()
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(msg), "timeout") {
		return errors.New("TIMEOUT")
	}
	if strings.Contains(strings.ToLower(msg), "connection refused") {
		return errors.New("CONN_REFUSED")
	}
	if strings.Contains(strings.ToLower(msg), "no such host") {
		// For .onion, this usually indicates DNS leak or proxy misconfig
		return errors.New("NO_SUCH_HOST (check Tor proxy / DNS leak)")
	}
	return err
}

// ----------------------------- Tor IP check ---------------------------

type torIPResp struct {
	IsTor bool   `json:"IsTor"`
	IP    string `json:"IP"`
}

func checkTorIP(client *http.Client) (ip string, isTor bool, err error) {
	// This endpoint returns JSON like {"IsTor":true,"IP":"x.x.x.x"}
	const api = "https://check.torproject.org/api/ip"
	status, body, _, err := fetchHTML(client, api, 30*time.Second, 128*1024)
	if err != nil {
		return "", false, err
	}
	if status < 200 || status >= 400 {
		return "", false, fmt.Errorf("tor ip check http %d", status)
	}
	var r torIPResp
	if jerr := json.Unmarshal(body, &r); jerr != nil {
		return "", false, jerr
	}
	return r.IP, r.IsTor, nil
}

// ----------------------------- Output --------------------------------

func writeLog(w io.Writer, format string, args ...any) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(w, "%s "+format+"\n", append([]any{ts}, args...)...)
}

func writeJSONL(f *os.File, mu *sync.Mutex, res Result) {
	mu.Lock()
	defer mu.Unlock()
	b, _ := json.Marshal(res)
	f.Write(b)
	f.Write([]byte("\n"))
}

func safeName(u string) string {
	pu, err := url.Parse(u)
	if err != nil || pu.Host == "" {
		return "badurl_" + shortHash(u)
	}
	host := strings.ReplaceAll(pu.Host, ":", "_")
	// include path/query via hash to avoid collisions
	return host + "_" + shortHash(u)
}

func shortHash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])[:10]
}

// ----------------------------- Screenshot ----------------------------

func autoDetectChrome() string {
	// Keep this simple: common paths for Windows/macOS/Linux.
	// User can always pass -chrome=PATH.
	if runtime.GOOS == "windows" {
		candidates := []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("LocalAppData"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		}
		for _, p := range candidates {
			if p != "" {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
		return ""
	}

	// macOS default
	if runtime.GOOS == "darwin" {
		candidates := []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return ""
	}

	// Linux: rely on PATH
	candidates := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "microsoft-edge-stable"}
	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func takeScreenshotChrome(ctx context.Context, chromeExe, targetURL, outPngPath, socksAddr string) error {
	// Chrome headless screenshot through SOCKS5.
	// NOTE: Depending on platform/build, SOCKS DNS handling may vary.
	// If you see NO_SUCH_HOST for .onion, prefer using Tor Browser for screenshots or disable screenshots.

	// Ensure output directory exists (even if caller already created it).
	if err := os.MkdirAll(filepath.Dir(outPngPath), 0o755); err != nil {
		return err
	}

	// Prefer an absolute + slash-normalized path for Chrome.
	// This avoids cases (seen on Windows) where Chrome resolves relative paths
	// against its own working directory and silently produces no screenshot file.
	absPng := outPngPath
	if p, err := filepath.Abs(outPngPath); err == nil {
		absPng = filepath.ToSlash(p)
	}

	// Use a temp user profile to reduce interference from a running Chrome instance.
	tmpProfile, err := os.MkdirTemp("", "tor-scraper-chrome-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpProfile)
	proxyArg := "socks5://" + socksAddr

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--hide-scrollbars",
		"--no-first-run",
		"--no-default-browser-check",
		"--user-data-dir=" + filepath.ToSlash(tmpProfile),
		"--proxy-server=" + proxyArg,
		"--proxy-bypass-list=<-loopback>",
		"--window-size=1366,768",
		"--screenshot=" + absPng,
		"--virtual-time-budget=30000",
		targetURL,
	}

	cmd := exec.CommandContext(ctx, chromeExe, args...)
	// Reduce noise; capture stderr for debugging
	var stderr strings.Builder
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	err = cmd.Run()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("screenshot TIMEOUT")
		}
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("screenshot failed: %v (%s)", err, msg)
		}
		return fmt.Errorf("screenshot failed: %v", err)
	}

	// Verify output exists
	if fi, err := os.Stat(absPng); err != nil || fi.Size() == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("screenshot produced no file (chrome stderr: %s)", msg)
		}
		return errors.New("screenshot produced no file")
	}
	return nil
}
