// Copyright © 2026 Hanzo AI. MIT License.

// Command cyber runs Hanzo Cyber's native zip control plane, MCP server,
// OpenAPI 3.1 contract exporter, and environment diagnostics.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hanzoai/cyber/pkg/control"
	"github.com/hanzoai/cyber/pkg/policy"
	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
	"github.com/zap-proto/zip/middleware"
)

var version = "1.0.0-beta.3"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "cyber: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return nil
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "mcp":
		return runMCP(args[1:])
	case "openapi":
		return runOpenAPI(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return nil
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `Hanzo Cyber %s — native zip control plane & MCP server

Usage:
  cyber <command> [flags]

Commands:
  serve      Start HTTP/ZAP control plane (/v1/cyber/*, /mcp, /.well-known/openapi.json, /.well-known/zip/op/) and @hanzo/gui console
  mcp        Run Model Context Protocol server over stdio (default) or HTTP (--addr)
  audit      Verify offline SHA-256 hash-chained audit logs (JSONL files or SQLite store)
  openapi    Print the OpenAPI 3.1 JSON specification derived from typed zip ops
  doctor     Verify SQLite driver, zip control surface, cyber-probe, web console, and Hanzo Router/Sandbox wiring
  version    Print the semantic version (%s)
`, version, version)
}

func defaultDataDir() string {
	if v := strings.TrimSpace(os.Getenv("HANZO_CYBER_DATA_DIR")); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".hanzo-cyber"
	}
	return filepath.Join(home, ".hanzo", "cyber")
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func buildApp(logger luxlog.Logger, store *control.Store, engine *control.Engine, standalone bool) *zip.App {
	app := zip.New(zip.Config{
		AppName:               "cyber",
		Logger:                logger,
		DisableStartupMessage: true,
		OpenAPI: zip.OpenAPIConfig{
			Title:       "Hanzo Cyber Control Plane",
			Version:     version,
			Description: "Native zip control plane for authorized cyber engagements, task reasoning graphs, verbatim proof verification, Kai risk governance, and Enso/Zen operator chat.",
		},
		MCP: zip.MCPConfig{
			Name: "hanzo-cyber",
		},
	})
	app.Use(
		zip.H(middleware.Recover()),
		zip.H(middleware.RequestID()),
		zip.H(middleware.CORS(middleware.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowHeaders: []string{"Content-Type", "Authorization", "X-Org-Id", "X-User-Id", "X-Request-Id"},
		})),
	)
	control.Mount(app, store, engine, control.MountConfig{
		Standalone: standalone,
	})
	return app
}

func normalizeHTTPAddr(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		a = ":8787"
	}
	if strings.Contains(a, "://") {
		return a
	}
	return "http://" + a
}

func resolveWebDir(override string) string {
	candidates := []string{strings.TrimSpace(override), strings.TrimSpace(os.Getenv("HANZO_CYBER_WEB_DIR"))}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates,
			filepath.Join(filepath.Dir(exe), "web", "dist"),
			filepath.Join(filepath.Dir(exe), "..", "web", "dist"),
		)
	}
	candidates = append(candidates, "web/dist", "/opt/hanzo/cyber/web/dist")
	for _, c := range candidates {
		if c == "" {
			continue
		}
		abs, err := filepath.Abs(expandHome(c))
		if err != nil {
			continue
		}
		if st, err := os.Stat(filepath.Join(abs, "index.html")); err == nil && !st.IsDir() {
			return abs
		}
	}
	return ""
}

func mountWebConsole(app *zip.App, webDir string) {
	if app == nil || webDir == "" {
		return
	}
	root := filepath.Clean(webDir)
	indexPath := filepath.Join(root, "index.html")
	serveStatic := func(c *zip.Ctx) error {
		p := c.Path()
		if strings.HasPrefix(p, "/v1/") || p == "/mcp" || strings.HasPrefix(p, "/.well-known/") || p == "/docs" {
			return c.Next()
		}
		rel := strings.TrimPrefix(filepath.Clean("/"+p), "/")
		if rel != "" && rel != "." {
			candidate := filepath.Join(root, rel)
			if strings.HasPrefix(candidate, root+string(os.PathSeparator)) {
				if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
					return c.Fiber().SendFile(candidate)
				}
			}
		}
		return c.Fiber().SendFile(indexPath)
	}
	for _, route := range []string{
		"/", "/assets/*", "/cyber", "/cyber/*",
		"/overview", "/graph", "/findings", "/approvals", "/traffic", "/chat", "/attack", "/coa", "/hardening", "/system",
		"/favicon.ico", "/favicon.svg", "/robots.txt",
	} {
		app.Raw(http.MethodGet, route, serveStatic)
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8787", "HTTP listen address (e.g. :8787 or http://127.0.0.1:8787)")
	zapAddr := fs.String("zap-addr", "", "Optional ZAP binary transport address (e.g. :9653 or /tmp/cyber.sock)")
	dataDir := fs.String("data-dir", defaultDataDir(), "Directory for SQLite control plane state")
	webDirFlag := fs.String("web-dir", "", "Directory containing compiled @hanzo/gui web console (defaults to HANZO_CYBER_WEB_DIR or ./web/dist)")
	standalone := fs.Bool("standalone", true, "Default missing identity headers to org 'local'")
	model := fs.String("model", "", "Default Enso/Zen model (defaults to HANZO_CYBER_MODEL or enso-auto)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir := expandHome(*dataDir)
	store, err := control.OpenStore(dir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = store.Close() }()

	engine := control.NewEngine(store, control.EngineConfig{
		Model:      *model,
		Standalone: *standalone,
	})
	logger := luxlog.NewWriter(os.Stderr)
	app := buildApp(logger, store, engine, *standalone)
	webDir := resolveWebDir(*webDirFlag)
	mountWebConsole(app, webDir)

	addrs := []string{normalizeHTTPAddr(*addr)}
	if z := strings.TrimSpace(*zapAddr); z != "" {
		addrs = append(addrs, z)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Listen(addrs...)
	}()

	logger.Info("hanzo cyber control plane listening",
		"version", version,
		"addrs", strings.Join(addrs, ","),
		"db", store.Path(),
		"webDir", webDir,
		"probe", engine.ProbePath(),
		"standalone", *standalone,
	)

	select {
	case sig := <-sigCh:
		logger.Info("shutting down cyber control plane", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return app.ShutdownWithContext(ctx)
	case err := <-errCh:
		return err
	}
}

func runMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	addr := fs.String("addr", "", "Optional HTTP listen address to serve /mcp over HTTP (empty uses stdio)")
	dataDir := fs.String("data-dir", defaultDataDir(), "Directory for SQLite control plane state")
	org := fs.String("org", "local", "Default tenant org for stdio MCP calls")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := control.OpenStore(expandHome(*dataDir))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = store.Close() }()

	engine := control.NewEngine(store, control.EngineConfig{Standalone: true})
	logger := luxlog.NewWriter(os.Stderr)
	app := buildApp(logger, store, engine, true)

	if strings.TrimSpace(*addr) != "" {
		return app.Listen(normalizeHTTPAddr(*addr))
	}

	return serveMCPStdio(context.Background(), app, *org, os.Stdin, os.Stdout)
}

// serveMCPStdio bridges newline-delimited JSON-RPC 2.0 MCP frames on stdio
// directly to zip's native /mcp surface without extra transport duplication.
func serveMCPStdio(ctx context.Context, app *zip.App, org string, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	testCfg := zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true}

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/mcp", bytes.NewReader(line))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(zip.HeaderOrg, org)
		req.Header.Set(zip.HeaderUser, "mcp-stdio")

		resp, err := app.Test(req, testCfg)
		if err != nil {
			return fmt.Errorf("mcp dispatch: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode == http.StatusAccepted || len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s\n", bytes.TrimSpace(body)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func runOpenAPI(args []string) error {
	fs := flag.NewFlagSet("openapi", flag.ContinueOnError)
	compact := fs.Bool("compact", false, "Emit compact single-line JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := control.OpenMemoryStore()
	if err != nil {
		return fmt.Errorf("open memory store: %w", err)
	}
	defer func() { _ = store.Close() }()

	app := buildApp(luxlog.NewNoOpLogger(), store, control.NewEngine(store, control.EngineConfig{}), false)
	spec := app.OpenAPISpec()

	var raw []byte
	if *compact {
		raw, err = json.Marshal(spec)
	} else {
		raw, err = json.MarshalIndent(spec, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("marshal openapi spec: %w", err)
	}
	fmt.Println(string(raw))
	return nil
}

func runAudit(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: cyber audit verify [--file <events.jsonl> | --data-dir <dir> --org <org> --engagement <id>]")
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	filePath := fs.String("file", "", "Offline JSONL audit file to verify via SHA-256 hash chain")
	dataDir := fs.String("data-dir", defaultDataDir(), "Directory for SQLite control plane state")
	org := fs.String("org", "local", "Tenant org for SQLite audit chain verification")
	engID := fs.String("engagement", "", "Engagement ID for audit chain verification")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if fp := strings.TrimSpace(*filePath); fp != "" {
		f, err := os.Open(expandHome(fp))
		if err != nil {
			return fmt.Errorf("open audit file: %w", err)
		}
		defer func() { _ = f.Close() }()
		res := policy.VerifyChain(f, strings.TrimSpace(*engID))
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		if !res.Valid {
			return fmt.Errorf("audit verification failed: %s", res.Error)
		}
		return nil
	}

	store, err := control.OpenStore(expandHome(*dataDir))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = store.Close() }()
	rep, err := store.VerifyAuditChain(context.Background(), strings.TrimSpace(*org), strings.TrimSpace(*engID))
	if err != nil {
		return fmt.Errorf("verify sqlite audit chain: %w", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	if !rep.Valid {
		return fmt.Errorf("audit chain tampered: %s", rep.Error)
	}
	return nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "Directory for SQLite control plane state")
	asJSON := fs.Bool("json", false, "Emit structured JSON report")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir := expandHome(*dataDir)
	store, err := control.OpenStore(dir)
	if err != nil {
		return fmt.Errorf("sqlite store check failed: %w", err)
	}
	defer func() { _ = store.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Ping(ctx); err != nil {
		return fmt.Errorf("sqlite ping failed: %w", err)
	}

	engine := control.NewEngine(store, control.EngineConfig{Standalone: true})
	app := buildApp(luxlog.NewNoOpLogger(), store, engine, true)
	spec := app.OpenAPISpec()
	tools := app.MCPTools()

	pathsCount, opsCount := 0, 0
	switch p := spec["paths"].(type) {
	case map[string]map[string]any:
		pathsCount = len(p)
		for _, item := range p {
			opsCount += len(item)
		}
	case map[string]any:
		pathsCount = len(p)
		for _, raw := range p {
			if item, ok := raw.(map[string]any); ok {
				opsCount += len(item)
			}
		}
	}
	cfg := engine.Config()
	webDir := resolveWebDir("")

	report := map[string]any{
		"status":          "ok",
		"version":         version,
		"go":              runtime.Version(),
		"platform":        runtime.GOOS + "/" + runtime.GOARCH,
		"sqlitePath":      store.Path(),
		"openApiPaths":    pathsCount,
		"openApiOps":      opsCount,
		"mcpTools":        len(tools),
		"cyberProbeReady": engine.ProbeConfigured(),
		"cyberProbePath":  engine.ProbePath(),
		"webConsoleReady": webDir != "",
		"webDir":          webDir,
		"auditChainReady": true,
		"routerUrl":       cfg.RouterURL,
		"routerReady":     engine.RouterConfigured(),
		"sandboxUrl":      cfg.SandboxURL,
		"sandboxReady":    engine.SandboxConfigured(),
		"genRuntime":      cfg.GenRuntime,
		"defaultModel":    cfg.Model,
		"offlineFallback": !cfg.DisableOfflineFallback,
	}

	if *asJSON {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Hanzo Cyber Doctor (%s)\n", version)
	fmt.Printf("  Go runtime   : %s (%s/%s)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  SQLite store : ok (%s)\n", store.Path())
	fmt.Printf("  Zip surface  : %d OpenAPI paths (%d ops), %d MCP tools\n", pathsCount, opsCount, len(tools))
	fmt.Printf("  Rust probe   : ready=%v (%s)\n", engine.ProbeConfigured(), engine.ProbePath())
	fmt.Printf("  Web console  : ready=%v (%s)\n", webDir != "", webDir)
	fmt.Printf("  Audit chain  : SHA-256 hash-chained (offline verifiable)\n")
	fmt.Printf("  Hanzo Router : %s (configured=%v, model=%s)\n", cfg.RouterURL, engine.RouterConfigured(), cfg.Model)
	fmt.Printf("  Hanzo Sandbox: %s (configured=%v, runtime=%s)\n", cfg.SandboxURL, engine.SandboxConfigured(), cfg.GenRuntime)
	return nil
}
