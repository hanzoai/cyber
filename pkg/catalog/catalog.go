package catalog

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

//go:embed data/catalog.json
var embeddedCatalogJSON []byte

// ToolSpec describes one executable-backed security tool from catalog.py.
type ToolSpec struct {
	Name           string   `json:"name"`
	Executable     string   `json:"executable"`
	Category       string   `json:"category"`
	Description    string   `json:"description"`
	Required       bool     `json:"required"`
	OptionalReason string   `json:"optional_reason"`
	Dependencies   []string `json:"dependencies"`
}

// ToolAvailability reports host binary resolution for a ToolSpec.
type ToolAvailability struct {
	Available           bool     `json:"available"`
	Path                string   `json:"path,omitempty"`
	MissingDependencies []string `json:"missing_dependencies"`
	Required            bool     `json:"required"`
	OptionalReason      string   `json:"optional_reason"`
}

// Availability checks whether this tool's executable and all dependencies are on PATH.
func (s ToolSpec) Availability() ToolAvailability {
	return s.AvailabilityWith(exec.LookPath)
}

// AvailabilityWith resolves executables using a custom lookPath function (useful for tests).
func (s ToolSpec) AvailabilityWith(lookPath func(string) (string, error)) ToolAvailability {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	binPath, err := lookPath(s.Executable)
	missing := make([]string, 0)
	for _, dep := range s.Dependencies {
		if _, derr := lookPath(dep); derr != nil {
			missing = append(missing, dep)
		}
	}
	return ToolAvailability{
		Available:           err == nil && binPath != "" && len(missing) == 0,
		Path:                binPath,
		MissingDependencies: missing,
		Required:            s.Required,
		OptionalReason:      s.OptionalReason,
	}
}

// ToolEntry is one full tool contract and schema record from catalog.json.
type ToolEntry struct {
	Name                 string         `json:"name"`
	Kind                 string         `json:"kind"`
	Group                string         `json:"group"`
	Shape                Shape          `json:"shape"`
	Effects              []Effect       `json:"effects"`
	Scope                Scope          `json:"scope"`
	RequiresEngagement   bool           `json:"requires_engagement"`
	Destructive          bool           `json:"destructive"`
	OpenWorld            bool           `json:"open_world"`
	Idempotent           bool           `json:"idempotent"`
	ReturnsTargetContent bool           `json:"returns_target_content"`
	ErrorCodes           []string       `json:"error_codes"`
	Description          string         `json:"description"`
	InputSchema          map[string]any `json:"input_schema"`
	OutputSchema         map[string]any `json:"output_schema"`
	Annotations          map[string]any `json:"annotations"`
	Meta                 map[string]any `json:"meta"`
	Digest               string         `json:"digest"`

	// Executable metadata populated for kind == "executable" tools (excluded from canonical digest).
	Spec *ToolSpec `json:"-"`
}

// Contract extracts the ToolContract portion of a ToolEntry.
func (e *ToolEntry) Contract() ToolContract {
	return ToolContract{
		Name:                 e.Name,
		Kind:                 e.Kind,
		Group:                e.Group,
		Shape:                e.Shape,
		Effects:              append([]Effect(nil), e.Effects...),
		Scope:                e.Scope,
		RequiresEngagement:   e.RequiresEngagement,
		Destructive:          e.Destructive,
		OpenWorld:            e.OpenWorld,
		Idempotent:           e.Idempotent,
		ReturnsTargetContent: e.ReturnsTargetContent,
		ErrorCodes:           append([]string(nil), e.ErrorCodes...),
	}
}

// ExecutionMode returns the execution mode ("executable" or "native").
func (e *ToolEntry) ExecutionMode() string {
	return e.Kind
}

func (e *ToolEntry) canonicalMap(includeDigest bool) map[string]any {
	effects := make([]string, len(e.Effects))
	for i, eff := range e.Effects {
		effects[i] = string(eff)
	}
	errorCodes := append([]string{}, e.ErrorCodes...)
	if errorCodes == nil {
		errorCodes = []string{}
	}
	inputSchema := e.InputSchema
	if inputSchema == nil {
		inputSchema = map[string]any{}
	}
	annotations := e.Annotations
	if annotations == nil {
		annotations = map[string]any{}
	}
	meta := e.Meta
	if meta == nil {
		meta = map[string]any{}
	}
	var outputSchema any
	if e.OutputSchema != nil {
		outputSchema = e.OutputSchema
	}
	m := map[string]any{
		"annotations":            annotations,
		"description":            e.Description,
		"destructive":            e.Destructive,
		"effects":                effects,
		"error_codes":            errorCodes,
		"group":                  e.Group,
		"idempotent":             e.Idempotent,
		"input_schema":           inputSchema,
		"kind":                   e.Kind,
		"meta":                   meta,
		"name":                   e.Name,
		"open_world":             e.OpenWorld,
		"output_schema":          outputSchema,
		"requires_engagement":    e.RequiresEngagement,
		"returns_target_content": e.ReturnsTargetContent,
		"scope":                  string(e.Scope),
		"shape":                  string(e.Shape),
	}
	if includeDigest {
		m["digest"] = e.Digest
	}
	return m
}

// OptionalIntegration describes an excluded or optional executable adapter.
type OptionalIntegration struct {
	Reason       string
	Dependencies []string
}

// OptionalIntegrations mirrors OPTIONAL_INTEGRATIONS from catalog.py.
var OptionalIntegrations = map[string]OptionalIntegration{
	"terrascan": {Reason: "Upstream is archived and no longer maintained."},
	"scout":     {Reason: "ScoutSuite's sqlitedict dependency has unresolved CVE-2024-35515, rated critical by CISA-ADP."},
}

// ToolDependencies mirrors TOOL_DEPENDENCIES from catalog.py.
var ToolDependencies = map[string][]string{
	"rustscan":  {"nmap"},
	"autorecon": {"nmap"},
	"nxc":       {"nmap"},
}

type groupEntry struct {
	slug       string
	executable string
}

type toolGroupDef struct {
	category string
	entries  []groupEntry
}

// toolGroups preserves the exact 171 executable tools and registration order from catalog.py.
var toolGroups = []toolGroupDef{
	{"network", []groupEntry{
		{"nmap", "nmap"}, {"rustscan", "rustscan"}, {"masscan", "masscan"},
		{"autorecon", "autorecon"}, {"arp_scan", "arp-scan"}, {"netbios_scan", "nbtscan"},
		{"packet_capture", "tcpdump"}, {"packet_analysis", "tshark"}, {"network_mapper", "netdiscover"},
		{"socat", "socat"}, {"ip", "ip"},
	}},
	{"enumeration", []groupEntry{
		{"amass", "amass"}, {"subfinder", "subfinder"}, {"fierce", "fierce"},
		{"dnsenum", "dnsenum"}, {"theharvester", "theHarvester"}, {"enum4linux", "enum4linux"},
		{"enum4linux_ng", "enum4linux-ng"}, {"rpcclient", "rpcclient"}, {"smbmap", "smbmap"},
		{"netexec", "nxc"}, {"responder", "responder"}, {"recon_ng", "recon-ng"},
		{"spiderfoot", "spiderfoot"}, {"sherlock", "sherlock"}, {"shodan", "shodan"},
		{"censys", "censys"},
	}},
	{"web", []groupEntry{
		{"gobuster", "gobuster"}, {"ffuf", "ffuf"}, {"feroxbuster", "feroxbuster"},
		{"dirb", "dirb"}, {"dirsearch", "dirsearch"}, {"nikto", "nikto"},
		{"nuclei", "nuclei"}, {"sqlmap", "sqlmap"}, {"whatweb", "whatweb"},
		{"wpscan", "wpscan"}, {"wfuzz", "wfuzz"}, {"xsser", "xsser"},
		{"dotdotpwn", "dotdotpwn"}, {"katana", "katana"}, {"hakrawler", "hakrawler"},
		{"gau", "gau"}, {"urlfinder", "urlfinder"}, {"arjun", "arjun"},
		{"paramspider", "paramspider"}, {"x8", "x8"}, {"jaeles", "jaeles"},
		{"dalfox", "dalfox"}, {"httpx", "httpx"}, {"anew", "anew"},
		{"qsreplace", "qsreplace"}, {"uro", "uro"}, {"wafw00f", "wafw00f"},
		{"zap", "zaproxy"}, {"subzy", "subzy"}, {"curl", "curl"}, {"httpie", "http"},
	}},
	{"credentials", []groupEntry{
		{"hydra", "hydra"}, {"medusa", "medusa"}, {"patator", "patator"},
		{"john", "john"}, {"hashcat", "hashcat"}, {"hash_identifier", "hash-identifier"},
		{"ophcrack", "ophcrack"}, {"evil_winrm", "evil-winrm"},
	}},
	{"exploitation", []groupEntry{
		{"exploit_search", "searchsploit"},
	}},
	{"binary", []groupEntry{
		{"gdb", "gdb"}, {"radare2", "radare2"}, {"ghidra", "ghidra"},
		{"binwalk", "binwalk"}, {"ropgadget", "ROPgadget"}, {"ropper", "ropper"},
		{"checksec", "checksec"}, {"objdump", "objdump"}, {"strings", "strings"},
		{"xxd", "xxd"}, {"file", "file"}, {"one_gadget", "one_gadget"},
		{"pwninit", "pwninit"}, {"pwntools", "pwn"},
	}},
	{"forensics", []groupEntry{
		{"volatility", "vol"}, {"foremost", "foremost"}, {"steghide", "steghide"},
		{"exiftool", "exiftool"}, {"testdisk", "testdisk"}, {"scalpel", "scalpel"},
		{"bulk_extractor", "bulk_extractor"}, {"zsteg", "zsteg"}, {"hashpump", "hashpump"},
		{"sleuthkit_fls", "fls"}, {"sleuthkit_icat", "icat"},
	}},
	{"cloud_container_iac", []groupEntry{
		{"prowler", "prowler"}, {"scout_suite", "scout"}, {"trivy", "trivy"},
		{"kube_hunter", "kube-hunter"}, {"kube_bench", "kube-bench"},
		{"docker_bench", "docker-bench-security"}, {"checkov", "checkov"}, {"terrascan", "terrascan"},
	}},
	{"wireless", []groupEntry{
		{"aircrack", "aircrack-ng"}, {"airmon", "airmon-ng"}, {"airodump", "airodump-ng"},
		{"aireplay", "aireplay-ng"}, {"kismet", "kismet"},
	}},
	{"rf", []groupEntry{
		{"hackrf_info", "hackrf_info"}, {"hackrf_transfer", "hackrf_transfer"},
		{"hackrf_sweep", "hackrf_sweep"}, {"rtl_sdr", "rtl_sdr"}, {"rtl_test", "rtl_test"},
		{"rtl_power", "rtl_power"}, {"rtl_433", "rtl_433"}, {"soapy_sdr", "SoapySDRUtil"},
		{"limesdr", "LimeUtil"}, {"bladerf", "bladeRF-cli"}, {"ubertooth_util", "ubertooth-util"},
		{"ubertooth_rx", "ubertooth-rx"}, {"ubertooth_scan", "ubertooth-scan"},
	}},
	{"wireless_attack", []groupEntry{
		{"iw", "iw"}, {"iwconfig", "iwconfig"}, {"wifite", "wifite"},
		{"hcxdumptool", "hcxdumptool"}, {"hcxpcapngtool", "hcxpcapngtool"},
		{"reaver", "reaver"}, {"bully", "bully"}, {"pixiewps", "pixiewps"},
		{"mdk4", "mdk4"}, {"cowpatty", "cowpatty"}, {"bluetoothctl", "bluetoothctl"},
		{"btmon", "btmon"}, {"hcitool", "hcitool"}, {"btmgmt", "btmgmt"},
	}},
	{"nfc_rfid", []groupEntry{
		{"proxmark3", "proxmark3"}, {"nfc_list", "nfc-list"}, {"nfc_poll", "nfc-poll"},
		{"nfc_mfclassic", "nfc-mfclassic"}, {"mfoc", "mfoc"}, {"mfcuk", "mfcuk"},
		{"pcsc_scan", "pcsc_scan"},
	}},
	{"usb", []groupEntry{
		{"lsusb", "lsusb"}, {"usbguard", "usbguard"},
	}},
	{"embedded", []groupEntry{
		{"openocd", "openocd"}, {"urjtag", "jtag"}, {"avrdude", "avrdude"},
		{"dfu_util", "dfu-util"}, {"esptool", "esptool"}, {"st_info", "st-info"},
		{"st_flash", "st-flash"}, {"minicom", "minicom"}, {"picocom", "picocom"},
		{"screen", "screen"}, {"flashrom", "flashrom"}, {"sigrok_cli", "sigrok-cli"},
		{"qemu_arm", "qemu-arm"}, {"qemu_system_arm", "qemu-system-arm"},
		{"gdb_multiarch", "gdb-multiarch"}, {"unblob", "unblob"},
	}},
	{"automotive", []groupEntry{
		{"candump", "candump"}, {"cansend", "cansend"}, {"cansniffer", "cansniffer"},
		{"canbusload", "canbusload"}, {"isotpsend", "isotpsend"}, {"isotprecv", "isotprecv"},
	}},
	{"gps", []groupEntry{
		{"gpsmon", "gpsmon"}, {"gpspipe", "gpspipe"}, {"gpsfake", "gpsfake"},
	}},
	{"ir", []groupEntry{
		{"lircd", "lircd"},
	}},
	{"mobile", []groupEntry{
		{"apktool", "apktool"}, {"jadx", "jadx"},
	}},
	{"utilities", []groupEntry{
		{"grep", "grep"}, {"jq", "jq"},
	}},
}

var nonAlnumRe = regexp.MustCompile(`[^a-z0-9_]+`)

func toolNameFromSlug(slug string) string {
	normalized := strings.Trim(nonAlnumRe.ReplaceAllString(strings.ToLower(slug), "_"), "_")
	return "oc_" + normalized
}

func buildExecutableSpecs() []ToolSpec {
	specs := make([]ToolSpec, 0, 171)
	seen := make(map[string]struct{}, 171)
	for _, grp := range toolGroups {
		for _, item := range grp.entries {
			name := toolNameFromSlug(item.slug)
			if _, dup := seen[name]; dup {
				panic("duplicate OpenCyber tool name: " + name)
			}
			seen[name] = struct{}{}
			opt, isOpt := OptionalIntegrations[item.executable]
			var deps []string
			if isOpt {
				deps = append([]string(nil), opt.Dependencies...)
			} else if d, ok := ToolDependencies[item.executable]; ok {
				deps = append([]string(nil), d...)
			}
			specs = append(specs, ToolSpec{
				Name:           name,
				Executable:     item.executable,
				Category:       grp.category,
				Required:       !isOpt,
				OptionalReason: opt.Reason,
				Dependencies:   deps,
			})
		}
	}
	return specs
}

// SearchFilter narrows a catalog query.
type SearchFilter struct {
	Name          string
	Query         string
	Category      string
	ExecutionMode string // "executable" or "native"
	Shape         Shape
	Scope         Scope
	Limit         int
	Offset        int
}

// Catalog provides indexed read-only access to the full Hanzo Cyber tool catalog.
type Catalog struct {
	manifest     *Manifest
	tools        []*ToolEntry
	byName       map[string]*ToolEntry
	byCategory   map[string][]*ToolEntry
	byMode       map[string][]*ToolEntry
	execSpecs    []ToolSpec
	specByName   map[string]ToolSpec
	specByBinary map[string]ToolSpec
}

var (
	defaultOnce sync.Once
	defaultCat  *Catalog
	defaultErr  error
)

// Default returns the embedded 271-tool catalog singleton.
func Default() *Catalog {
	defaultOnce.Do(func() {
		defaultCat, defaultErr = LoadBytes(embeddedCatalogJSON)
	})
	if defaultErr != nil {
		panic("failed to load embedded catalog.json: " + defaultErr.Error())
	}
	return defaultCat
}

// LoadBytes parses a catalog.json manifest and indexes all tools.
func LoadBytes(data []byte) (*Catalog, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("invalid catalog manifest JSON: %v", err), ocerrors.WithCause(err))
	}

	execSpecs := buildExecutableSpecs()
	specByName := make(map[string]ToolSpec, len(execSpecs))
	specByBinary := make(map[string]ToolSpec, len(execSpecs))
	for _, spec := range execSpecs {
		specByName[spec.Name] = spec
		specByBinary[spec.Executable] = spec
	}

	c := &Catalog{
		manifest:     &m,
		tools:        make([]*ToolEntry, 0, len(m.Tools)),
		byName:       make(map[string]*ToolEntry, len(m.Tools)),
		byCategory:   make(map[string][]*ToolEntry),
		byMode:       make(map[string][]*ToolEntry),
		execSpecs:    execSpecs,
		specByName:   specByName,
		specByBinary: specByBinary,
	}

	for _, entry := range m.Tools {
		if entry == nil {
			continue
		}
		if spec, ok := specByName[entry.Name]; ok {
			spec.Description = entry.Description
			cp := spec
			entry.Spec = &cp
			specByName[entry.Name] = cp
			specByBinary[cp.Executable] = cp
		}
		c.tools = append(c.tools, entry)
		c.byName[entry.Name] = entry
		c.byCategory[entry.Group] = append(c.byCategory[entry.Group], entry)
		c.byMode[entry.Kind] = append(c.byMode[entry.Kind], entry)
	}
	// Refresh execSpecs slice with descriptions from manifest.
	for i, spec := range c.execSpecs {
		if updated, ok := c.specByName[spec.Name]; ok {
			c.execSpecs[i] = updated
		}
	}
	return c, nil
}

// Manifest returns the underlying parsed Manifest.
func (c *Catalog) Manifest() *Manifest {
	return c.manifest
}

// Len returns the total number of tools in the catalog.
func (c *Catalog) Len() int {
	return len(c.tools)
}

// All returns all tool entries sorted by name.
func (c *Catalog) All() []*ToolEntry {
	out := make([]*ToolEntry, len(c.tools))
	copy(out, c.tools)
	return out
}

// ByName looks up a tool by exact MCP name (e.g., "oc_nmap").
func (c *Catalog) ByName(name string) (*ToolEntry, bool) {
	entry, ok := c.byName[name]
	return entry, ok
}

// Tool looks up a tool by exact name, returning unknown_tool *Error if missing.
func (c *Catalog) Tool(name string) (*ToolEntry, error) {
	entry, ok := c.byName[name]
	if !ok {
		return nil, ocerrors.New(
			ocerrors.CodeUnknownTool,
			fmt.Sprintf("unknown OpenCyber tool: %s", name),
			ocerrors.WithDetail("tool", name),
		)
	}
	return entry, nil
}

// Contract returns the ToolContract for name, or unknown_tool *Error if missing.
func (c *Catalog) Contract(name string) (*ToolContract, error) {
	entry, err := c.Tool(name)
	if err != nil {
		return nil, err
	}
	contract := entry.Contract()
	return &contract, nil
}

// ByCategory returns all tools belonging to the given category/group.
func (c *Catalog) ByCategory(category string) []*ToolEntry {
	entries := c.byCategory[category]
	out := make([]*ToolEntry, len(entries))
	copy(out, entries)
	return out
}

// ByExecutionMode returns all tools matching the execution mode ("executable" or "native").
func (c *Catalog) ByExecutionMode(mode string) []*ToolEntry {
	entries := c.byMode[mode]
	out := make([]*ToolEntry, len(entries))
	copy(out, entries)
	return out
}

// ByShape returns all tools matching the given analyst task Shape.
func (c *Catalog) ByShape(shape Shape) []*ToolEntry {
	var out []*ToolEntry
	for _, entry := range c.tools {
		if entry.Shape == shape {
			out = append(out, entry)
		}
	}
	return out
}

// ByScope returns all tools matching the given enforcement Scope.
func (c *Catalog) ByScope(scope Scope) []*ToolEntry {
	var out []*ToolEntry
	for _, entry := range c.tools {
		if entry.Scope == scope {
			out = append(out, entry)
		}
	}
	return out
}

// ExecutableSpecs returns all 171 executable-backed ToolSpec descriptors.
func (c *Catalog) ExecutableSpecs() []ToolSpec {
	out := make([]ToolSpec, len(c.execSpecs))
	copy(out, c.execSpecs)
	return out
}

// ExecutableSpec looks up the ToolSpec for an executable tool by MCP name.
func (c *Catalog) ExecutableSpec(name string) (ToolSpec, bool) {
	spec, ok := c.specByName[name]
	return spec, ok
}

// ByExecutable looks up the ToolSpec by OS binary name (e.g., "nmap", "tshark").
func (c *Catalog) ByExecutable(binary string) (ToolSpec, bool) {
	spec, ok := c.specByBinary[binary]
	return spec, ok
}

// CategoryCounts returns a map of category/group name to tool count.
func (c *Catalog) CategoryCounts() map[string]int {
	counts := make(map[string]int, len(c.byCategory))
	for cat, entries := range c.byCategory {
		counts[cat] = len(entries)
	}
	return counts
}

// Search filters tools by exact name, substring query, category, execution mode,
// shape, scope, and optional offset/limit paging.
func (c *Catalog) Search(filter SearchFilter) []*ToolEntry {
	q := strings.ToLower(strings.TrimSpace(filter.Query))
	var matched []*ToolEntry
	for _, entry := range c.tools {
		if filter.Name != "" && entry.Name != filter.Name {
			continue
		}
		if filter.Category != "" && entry.Group != filter.Category {
			continue
		}
		if filter.ExecutionMode != "" && entry.Kind != filter.ExecutionMode {
			continue
		}
		if filter.Shape != "" && entry.Shape != filter.Shape {
			continue
		}
		if filter.Scope != "" && entry.Scope != filter.Scope {
			continue
		}
		if q != "" {
			execName := ""
			if entry.Spec != nil {
				execName = strings.ToLower(entry.Spec.Executable)
			}
			if !strings.Contains(strings.ToLower(entry.Name), q) &&
				!strings.Contains(strings.ToLower(entry.Description), q) &&
				!strings.Contains(strings.ToLower(entry.Group), q) &&
				!strings.Contains(execName, q) {
				continue
			}
		}
		matched = append(matched, entry)
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return []*ToolEntry{}
		}
		matched = matched[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(matched) {
		matched = matched[:filter.Limit]
	}
	return matched
}

// ValidateAdvertised fails if any advertised tool name has no declared contract.
func (c *Catalog) ValidateAdvertised(advertised []string) error {
	var missing []string
	seen := make(map[string]struct{}, len(advertised))
	for _, name := range advertised {
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		if _, ok := c.byName[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return ocerrors.New(
			ocerrors.CodeUnknownTool,
			"advertised tools without a contract: "+strings.Join(missing, ", "),
			ocerrors.WithDetail("missing_tools", missing),
		)
	}
	return nil
}

// ValidateArguments validates args against the named tool's input_schema.
func (c *Catalog) ValidateArguments(toolName string, args map[string]any) error {
	entry, err := c.Tool(toolName)
	if err != nil {
		return err
	}
	return entry.ValidateArguments(args)
}

// ReferenceCoverage computes functional inventory coverage against errors.ReferenceFunctions.
func (c *Catalog) ReferenceCoverage() ocerrors.ReferenceCoverageReport {
	byExec := make(map[string]string, len(c.execSpecs))
	for _, spec := range c.execSpecs {
		byExec[spec.Executable] = spec.Name
	}
	return ocerrors.ComputeReferenceCoverage(byExec)
}

// Digest computes the deterministic SHA-256 catalog digest across all tools in this catalog.
func (c *Catalog) Digest() (string, error) {
	return CatalogSHA256(c.tools)
}
