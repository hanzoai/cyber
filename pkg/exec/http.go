package exec

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultHTTPTimeoutSeconds = 30.0
	MaxHTTPTimeoutSeconds     = 300.0
	HTTPTimeoutEnv            = "OPENCYBER_HTTP_TIMEOUT"
	DefaultMaxResponseBytes   = 262144 // 256 KiB
	DefaultMaxRedirects       = 10
	MaxAllowedRedirects       = 30
)

// ResolveHTTPTimeout resolves and validates a native HTTP timeout in seconds.
// Zero, negative, non-finite, or values exceeding 300s are rejected rather than clamped.
func ResolveHTTPTimeout(override *float64) (time.Duration, error) {
	var val float64
	if override == nil {
		raw := strings.TrimSpace(os.Getenv(HTTPTimeoutEnv))
		if raw == "" {
			return time.Duration(DefaultHTTPTimeoutSeconds * float64(time.Second)), nil
		}
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return 0, NewError("invalid_argument", fmt.Sprintf("%s must be a number of seconds, got %q", HTTPTimeoutEnv, raw))
		}
		val = parsed
	} else {
		val = *override
	}
	if math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 || val > MaxHTTPTimeoutSeconds {
		return 0, NewError("invalid_argument",
			fmt.Sprintf("timeout must be greater than 0 and at most %g seconds", MaxHTTPTimeoutSeconds))
	}
	return time.Duration(val * float64(time.Second)), nil
}

// RedirectHop records one followed HTTP redirect.
type RedirectHop struct {
	Status   int    `json:"status"`
	URL      string `json:"url"`
	Location string `json:"location"`
}

// HTTPRequest describes a single bounded HTTP call.
type HTTPRequest struct {
	Method          string
	URL             string
	Headers         map[string]string
	Body            string
	FollowRedirects *bool // nil = true
	TimeoutSeconds  *float64
	EngagementID    string
	Tool            string
	VerifyTLS       *bool // nil = true
	MaxRedirects    int   // 0 = client default
}

// HTTPResponse is the structured, bounded result of an HTTP call.
type HTTPResponse struct {
	Status        int               `json:"status"`
	URL           string            `json:"url"`
	RequestedURL  string            `json:"requested_url"`
	Headers       map[string]string `json:"headers"`
	RawHeaders    http.Header       `json:"-"`
	Body          string            `json:"body"`
	BodyBytes     int               `json:"body_bytes"`
	Truncated     bool              `json:"truncated"`
	ScopeEnforced bool              `json:"scope_enforced"`
	RedirectChain []RedirectHop     `json:"redirect_chain,omitempty"`
	ElapsedMS     float64           `json:"elapsed_ms"`
	Coverage      *Coverage         `json:"coverage"`
	Limitations   []string          `json:"limitations"`
	Limit         *LimitFacts       `json:"limit,omitempty"`
}

// HTTPClient performs scope-enforced, size-bounded, timeout-capped HTTP requests.
type HTTPClient struct {
	Scope            ScopeValidator
	Blocklist        TargetBlocklist
	Governor         RateGovernor
	MaxResponseBytes int
	MaxRedirects     int
	UserAgent        string
	Transport        http.RoundTripper
}

// NewHTTPClient creates a bounded HTTPClient with sensible defaults.
func NewHTTPClient(scope ScopeValidator) *HTTPClient {
	return &HTTPClient{
		Scope:            scope,
		MaxResponseBytes: DefaultMaxResponseBytes,
		MaxRedirects:     DefaultMaxRedirects,
		UserAgent:        "hanzo-cyber/" + Version,
	}
}

func (c *HTTPClient) maxResponseBytes() int {
	if c != nil && c.MaxResponseBytes > 0 {
		return c.MaxResponseBytes
	}
	return DefaultMaxResponseBytes
}

func (c *HTTPClient) maxRedirects(reqMax int) int {
	if reqMax > 0 {
		if reqMax > MaxAllowedRedirects {
			return MaxAllowedRedirects
		}
		return reqMax
	}
	if c != nil && c.MaxRedirects > 0 {
		return c.MaxRedirects
	}
	return DefaultMaxRedirects
}

func (c *HTTPClient) transportFor(verifyTLS bool) http.RoundTripper {
	if c != nil && c.Transport != nil {
		return c.Transport
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	if !verifyTLS {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{}
		}
		base.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // operator explicitly requested VerifyTLS=false for self-signed assessment targets
	}
	return base
}

func (c *HTTPClient) checkTarget(engagementID, rawURL, tool string) (ScopeDecision, error) {
	u, err := CanonicalHTTPURL(rawURL)
	if err != nil {
		return ScopeDecision{}, err
	}
	var dec ScopeDecision
	if c != nil && c.Scope != nil {
		dec, err = c.Scope.CheckURL(engagementID, rawURL, tool)
		if err != nil {
			return dec, err
		}
	} else {
		dec = ScopeDecision{Enforced: false, Allowed: true, Host: strings.ToLower(u.Hostname())}
	}
	if c != nil && c.Blocklist != nil {
		if pattern, blocked := c.Blocklist.IsBlocked(engagementID, strings.ToLower(u.Hostname()), rawURL); blocked {
			return dec, NewError("scope_denied", fmt.Sprintf("target blocklist refused %s", pattern),
				WithDetails(map[string]any{"tool": tool, "url": rawURL, "blocked_target": pattern}))
		}
	}
	return dec, nil
}

// Do executes one bounded HTTP request, checking scope on the initial URL and every redirect hop.
func (c *HTTPClient) Do(ctx context.Context, req HTTPRequest) (*HTTPResponse, error) {
	tool := req.Tool
	if tool == "" {
		tool = "oc_http_request"
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	timeout, err := ResolveHTTPTimeout(req.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	follow := true
	if req.FollowRedirects != nil {
		follow = *req.FollowRedirects
	}
	verifyTLS := true
	if req.VerifyTLS != nil {
		verifyTLS = *req.VerifyTLS
	}

	scopeDec, err := c.checkTarget(req.EngagementID, req.URL, tool)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		headers[k] = v
	}

	started := time.Now()
	client := &http.Client{
		Transport: c.transportFor(verifyTLS),
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	curURL := req.URL
	curMethod := method
	curBody := req.Body
	maxBytes := c.maxResponseBytes()
	maxHops := c.maxRedirects(req.MaxRedirects)
	var chain []RedirectHop

	for {
		var release func()
		if c != nil && c.Governor != nil {
			release, err = c.Governor.Acquire(ctx, curURL)
			if err != nil {
				return nil, err
			}
		}

		var bodyReader io.Reader
		if curBody != "" {
			bodyReader = strings.NewReader(curBody)
		}
		hreq, err := http.NewRequestWithContext(ctx, curMethod, curURL, bodyReader)
		if err != nil {
			if release != nil {
				release()
			}
			return nil, NewError("invalid_argument", fmt.Sprintf("invalid HTTP request: %v", err), WithCause(err))
		}
		hasUA := false
		for k, v := range headers {
			if strings.EqualFold(k, "User-Agent") {
				hasUA = true
			}
			hreq.Header.Set(k, v)
		}
		if !hasUA && c != nil && c.UserAgent != "" {
			hreq.Header.Set("User-Agent", c.UserAgent)
		}

		resp, err := client.Do(hreq)
		if release != nil {
			release()
		}
		if err != nil {
			return nil, classifyHTTPError(ctx, err)
		}
		if c != nil && c.Governor != nil {
			c.Governor.Observe(curURL, resp.StatusCode)
		}

		bodyBytes, truncated, readErr := readBoundedBody(resp.Body, maxBytes)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, classifyHTTPError(ctx, readErr)
		}

		loc := resp.Header.Get("Location")
		if follow && isRedirectStatus(resp.StatusCode) && loc != "" {
			if len(chain) >= maxHops {
				return nil, NewError("limit_exceeded", fmt.Sprintf("HTTP redirect chain exceeded %d redirects", maxHops))
			}
			baseParsed, _ := url.Parse(curURL)
			locParsed, perr := url.Parse(loc)
			if perr != nil {
				return nil, NewError("invalid_argument", fmt.Sprintf("invalid redirect Location %q: %v", loc, perr))
			}
			nextURL := baseParsed.ResolveReference(locParsed).String()
			if _, serr := c.checkTarget(req.EngagementID, nextURL, tool); serr != nil {
				return nil, serr
			}
			changed, cerr := CredentialBoundaryChanged(curURL, nextURL)
			if cerr != nil {
				return nil, cerr
			}
			if changed {
				stripSensitiveHeaders(headers)
			}
			chain = append(chain, RedirectHop{
				Status:   resp.StatusCode,
				URL:      curURL,
				Location: nextURL,
			})
			if resp.StatusCode == http.StatusSeeOther ||
				((resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound) && curMethod == http.MethodPost) {
				curMethod = http.MethodGet
				curBody = ""
			}
			curURL = nextURL
			continue
		}

		flatHeaders := flattenHeaders(resp.Header)
		covStatus := "complete"
		exhausted := true
		var limitations []string
		var limitFacts *LimitFacts
		if truncated {
			covStatus = "partial"
			exhausted = false
			limitations = []string{"The response body exceeded http.response_max_bytes; only its prefix is returned."}
			limitFacts = LimitHTTPResponseMaxBytes.Facts(float64(maxBytes), nil, "")
		} else {
			limitations = []string{}
		}

		return &HTTPResponse{
			Status:        resp.StatusCode,
			URL:           curURL,
			RequestedURL:  req.URL,
			Headers:       flatHeaders,
			RawHeaders:    resp.Header,
			Body:          string(bodyBytes),
			BodyBytes:     len(bodyBytes),
			Truncated:     truncated,
			ScopeEnforced: scopeDec.Enforced,
			RedirectChain: chain,
			ElapsedMS:     float64(time.Since(started).Microseconds()) / 1000.0,
			Coverage:      &Coverage{Status: covStatus, Exhausted: boolPtr(exhausted)},
			Limitations:   limitations,
			Limit:         limitFacts,
		}, nil
	}
}

// GraphQLRequest specifies one GraphQL POST call.
type GraphQLRequest struct {
	URL            string
	Query          string
	Variables      map[string]any
	Headers        map[string]string
	TimeoutSeconds *float64
	EngagementID   string
}

// GraphQLResponse is the bounded GraphQL response.
type GraphQLResponse struct {
	Status        int               `json:"status"`
	URL           string            `json:"url"`
	RequestedURL  string            `json:"requested_url"`
	Headers       map[string]string `json:"headers"`
	Response      any               `json:"response"`
	ScopeEnforced bool              `json:"scope_enforced"`
	Truncated     bool              `json:"truncated,omitempty"`
	Coverage      *Coverage         `json:"coverage,omitempty"`
	Limitations   []string          `json:"limitations,omitempty"`
	Limit         *LimitFacts       `json:"limit,omitempty"`
}

// GraphQL executes a bounded, scope-checked GraphQL query.
func (c *HTTPClient) GraphQL(ctx context.Context, req GraphQLRequest) (*GraphQLResponse, error) {
	vars := req.Variables
	if vars == nil {
		vars = map[string]any{}
	}
	payload, err := json.Marshal(map[string]any{
		"query":     req.Query,
		"variables": vars,
	})
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range req.Headers {
		headers[k] = v
	}
	resp, err := c.Do(ctx, HTTPRequest{
		Method:         http.MethodPost,
		URL:            req.URL,
		Headers:        headers,
		Body:           string(payload),
		TimeoutSeconds: req.TimeoutSeconds,
		EngagementID:   req.EngagementID,
		Tool:           "oc_graphql_request",
	})
	if err != nil {
		return nil, err
	}
	var parsed any
	if err := json.Unmarshal([]byte(resp.Body), &parsed); err != nil {
		parsed = resp.Body
	}
	return &GraphQLResponse{
		Status:        resp.Status,
		URL:           resp.URL,
		RequestedURL:  resp.RequestedURL,
		Headers:       resp.Headers,
		Response:      parsed,
		ScopeEnforced: resp.ScopeEnforced,
		Truncated:     resp.Truncated,
		Coverage:      resp.Coverage,
		Limitations:   resp.Limitations,
		Limit:         resp.Limit,
	}, nil
}

func readBoundedBody(r io.Reader, limit int) ([]byte, bool, error) {
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	buf := make([]byte, 0, min(limit, 32*1024))
	tmp := make([]byte, 32*1024)
	truncated := false
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			remaining := limit - len(buf)
			if remaining <= 0 {
				truncated = true
				break
			}
			if n > remaining {
				buf = append(buf, tmp[:remaining]...)
				truncated = true
				break
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return buf, truncated, err
		}
	}
	return buf, truncated, nil
}

func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func stripSensitiveHeaders(headers map[string]string) {
	for k := range headers {
		switch strings.ToLower(k) {
		case "authorization", "proxy-authorization", "cookie":
			delete(headers, k)
		}
	}
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

func classifyHTTPError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return NewError("cancelled", fmt.Sprintf("HTTP request cancelled: %v", err), WithCause(err))
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return NewError("timed_out", fmt.Sprintf("HTTP request timed out: %v", err), WithCause(err))
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return NewError("timed_out", fmt.Sprintf("HTTP request timed out: %v", err), WithCause(err))
	}
	var ocErr *Error
	if errors.As(err, &ocErr) {
		return ocErr
	}
	return NewError("connection_failed", err.Error(), WithCause(err))
}
