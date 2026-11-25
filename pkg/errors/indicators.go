package errors

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// RedactedPlaceholder is used when redacting sensitive HTTP headers.
const RedactedPlaceholder = "<redacted>"

// RedactedMask is used when redacting credential values in audit trails and logs.
const RedactedMask = "***"

var (
	urlRe    = regexp.MustCompile(`https?://[^\s"'<>]+`)
	ipv4Re   = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
	cveRe    = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	md5Re    = regexp.MustCompile(`(?i)\b[a-f0-9]{32}\b`)
	sha1Re   = regexp.MustCompile(`(?i)\b[a-f0-9]{40}\b`)
	sha256Re = regexp.MustCompile(`(?i)\b[a-f0-9]{64}\b`)
	ipv6Re   = regexp.MustCompile(`(?i)[a-f0-9:.]+`)
	domainRe = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)`)

	secretKeyRe = regexp.MustCompile(
		`(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|private[_-]?key|credential|passphrase|bearer)`,
	)
	secretValueRe = regexp.MustCompile(
		`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|passphrase|bearer)(\s*[:=]\s*)([^\s,;"']+)`,
	)
	bearerRe = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`)

	secretHeaders = map[string]struct{}{
		"authorization":       {},
		"proxy-authorization": {},
		"cookie":              {},
		"set-cookie":          {},
		"x-api-key":           {},
		"x-auth-token":        {},
		"x-csrf-token":        {},
	}
)

// Indicators holds deduplicated, sorted IOCs extracted offline from arbitrary text.
type Indicators struct {
	URLs    []string `json:"urls"`
	IPv4    []string `json:"ipv4"`
	CVEs    []string `json:"cves"`
	MD5     []string `json:"md5"`
	SHA1    []string `json:"sha1"`
	SHA256  []string `json:"sha256"`
	IPv6    []string `json:"ipv6,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

// ExtractIndicators extracts URLs, IPv4 addresses, CVEs, and cryptographic hashes
// without resolving names or contacting any service. When extended is true,
// normalized IPv6 addresses and domain names are also extracted.
func ExtractIndicators(text string, extended bool) Indicators {
	out := Indicators{
		URLs:   uniqueSorted(urlRe.FindAllString(text, -1)),
		IPv4:   extractIPv4(text),
		CVEs:   uniqueSorted(cveRe.FindAllString(text, -1)),
		MD5:    uniqueSorted(md5Re.FindAllString(text, -1)),
		SHA1:   uniqueSorted(sha1Re.FindAllString(text, -1)),
		SHA256: uniqueSorted(sha256Re.FindAllString(text, -1)),
	}
	if extended {
		out.IPv6 = extractIPv6(text)
		out.Domains = extractDomains(text)
	}
	return out
}

func extractIPv4(text string) []string {
	set := make(map[string]struct{})
	for _, loc := range ipv4Re.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if start > 0 && isWordOrDot(text[start-1]) {
			continue
		}
		if end < len(text) && isWordOrDot(text[end]) {
			continue
		}
		candidate := text[start:end]
		addr, err := netip.ParseAddr(candidate)
		if err != nil || !addr.Is4() {
			continue
		}
		set[candidate] = struct{}{}
	}
	return sortedKeys(set)
}

func extractIPv6(text string) []string {
	set := make(map[string]struct{})
	for _, loc := range ipv6Re.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if start > 0 && isWordOrColon(text[start-1]) {
			continue
		}
		if end < len(text) && isWordOrColon(text[end]) {
			continue
		}
		candidate := strings.TrimRight(text[start:end], ".")
		if len(candidate) > 45 || strings.Count(candidate, ":") < 2 {
			continue
		}
		addr, err := netip.ParseAddr(candidate)
		if err != nil || !addr.Is6() {
			continue
		}
		set[addr.String()] = struct{}{}
	}
	return sortedKeys(set)
}

func extractDomains(text string) []string {
	set := make(map[string]struct{})
	for _, loc := range domainRe.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if start > 0 && isDomainBoundaryChar(text[start-1]) {
			continue
		}
		if end < len(text) && isDomainBoundaryChar(text[end]) {
			continue
		}
		candidate := text[start:end]
		if len(candidate) > 253 {
			continue
		}
		set[strings.ToLower(candidate)] = struct{}{}
	}
	return sortedKeys(set)
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func isWordOrDot(b byte) bool {
	return isWordByte(b) || b == '.'
}

func isWordOrColon(b byte) bool {
	return isWordByte(b) || b == ':'
}

func isDomainBoundaryChar(b byte) bool {
	return isWordByte(b) || b == '.' || b == '-'
}

func uniqueSorted(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsSecretKey reports whether a field/header name looks like a credential or secret.
func IsSecretKey(key string) bool {
	return secretKeyRe.MatchString(key)
}

// RedactString masks bearer tokens and inline key=value / key:value secrets in free text.
func RedactString(s string) string {
	s = bearerRe.ReplaceAllString(s, "Bearer "+RedactedMask)
	return secretValueRe.ReplaceAllString(s, "${1}${2}"+RedactedMask)
}

// RedactValue recursively redacts values that look like credentials, tokens, or secrets.
func RedactValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return RedactMap(val)
	case map[string]string:
		out := make(map[string]string, len(val))
		for k, s := range val {
			if IsSecretKey(k) {
				out[k] = RedactedMask
			} else {
				out[k] = RedactString(s)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = RedactValue(item)
		}
		return out
	case []string:
		out := make([]string, len(val))
		for i, item := range val {
			out[i] = RedactString(item)
		}
		return out
	case string:
		return RedactString(val)
	default:
		return v
	}
}

// RedactMap returns a redacted deep copy of a JSON-like map.
func RedactMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if IsSecretKey(k) {
			out[k] = RedactedMask
		} else {
			out[k] = RedactValue(v)
		}
	}
	return out
}

// RedactHeaders returns a copy of HTTP headers with credential headers masked.
func RedactHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if _, secret := secretHeaders[strings.ToLower(strings.TrimSpace(k))]; secret {
			out[k] = RedactedPlaceholder
		} else {
			out[k] = v
		}
	}
	return out
}
