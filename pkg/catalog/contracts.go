// Package catalog embeds the canonical 271-tool Hanzo Cyber MCP contract
// manifest, provides indexed lookups and executable availability metadata,
// computes deterministic SHA-256 catalog identity digests and alignment
// reports, and validates tool call arguments against each tool's JSON Schema.
package catalog

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

// ContractSchemaVersion is the revision of the tool contract schema.
const ContractSchemaVersion = 1

// Shape describes the analyst task shape a tool serves.
type Shape string

const (
	ShapeInspect  Shape = "inspect"
	ShapeSearch   Shape = "search"
	ShapeTrace    Shape = "trace"
	ShapeCompare  Shape = "compare"
	ShapeWorkflow Shape = "workflow"
	ShapeObserve  Shape = "observe"
	ShapeExecute  Shape = "execute"
	ShapeManage   Shape = "manage"
)

// Effect describes an observable side effect a caller must assume before invocation.
type Effect string

const (
	EffectProcess    Effect = "process"
	EffectFilesystem Effect = "filesystem"
	EffectNetwork    Effect = "network"
	EffectDevice     Effect = "device"
	EffectSecret     Effect = "secret"
	EffectMutation   Effect = "mutation"
)

// Scope describes which enforcement boundary a tool's target crosses.
type Scope string

const (
	ScopeNone       Scope = "none"
	ScopeArgv       Scope = "argv"
	ScopeURL        Scope = "url"
	ScopeDevice     Scope = "device"
	ScopeEngagement Scope = "engagement"
)

// ToolAnnotations mirrors MCP ToolAnnotations hints derived from a contract.
type ToolAnnotations struct {
	Title           string `json:"title"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

// ToolContract is the declared authority of one advertised tool.
type ToolContract struct {
	Name                 string   `json:"name"`
	Kind                 string   `json:"kind"`
	Group                string   `json:"group"`
	Shape                Shape    `json:"shape"`
	Effects              []Effect `json:"effects"`
	Scope                Scope    `json:"scope"`
	RequiresEngagement   bool     `json:"requires_engagement"`
	Destructive          bool     `json:"destructive"`
	OpenWorld            bool     `json:"open_world"`
	Idempotent           bool     `json:"idempotent"`
	ReturnsTargetContent bool     `json:"returns_target_content"`
	ErrorCodes           []string `json:"error_codes"`
}

// ReadOnly reports whether the declared authority cannot mutate state.
func (c ToolContract) ReadOnly() bool {
	if c.Destructive {
		return false
	}
	for _, eff := range c.Effects {
		if eff == EffectMutation {
			return false
		}
	}
	return true
}

// ProvenanceSource identifies where returned facts come from for untrusted-content marking.
func (c ToolContract) ProvenanceSource() string {
	if c.ReturnsTargetContent {
		return "target"
	}
	if c.RequiresEngagement {
		return "engagement"
	}
	return "server"
}

// Title returns the human-readable title derived from the oc_* tool name.
func (c ToolContract) Title() string {
	trimmed := strings.TrimPrefix(c.Name, "oc_")
	parts := strings.Split(trimmed, "_")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		}
	}
	return strings.Join(parts, " ")
}

// Annotations returns MCP ToolAnnotations derived from this contract.
func (c ToolContract) Annotations() ToolAnnotations {
	return ToolAnnotations{
		Title:           c.Title(),
		ReadOnlyHint:    c.ReadOnly(),
		DestructiveHint: c.Destructive,
		IdempotentHint:  c.Idempotent,
		OpenWorldHint:   c.OpenWorld,
	}
}

// Meta returns the compact _meta.opencyber block advertised per tool.
func (c ToolContract) Meta() map[string]any {
	return map[string]any{
		"opencyber": map[string]any{
			"contract_schema_version": ContractSchemaVersion,
			"kind":                    c.Kind,
			"group":                   c.Group,
			"shape":                   string(c.Shape),
			"effects":                 sortedEffectStrings(c.Effects),
			"scope":                   string(c.Scope),
			"requires_engagement":     c.RequiresEngagement,
			"returns_target_content":  c.ReturnsTargetContent,
		},
	}
}

// AsMap returns the canonical map projection used by catalog identity digests.
func (c ToolContract) AsMap() map[string]any {
	codes := append([]string{}, c.ErrorCodes...)
	if codes == nil {
		codes = []string{}
	}
	return map[string]any{
		"name":                   c.Name,
		"kind":                   c.Kind,
		"group":                  c.Group,
		"shape":                  string(c.Shape),
		"effects":                sortedEffectStrings(c.Effects),
		"scope":                  string(c.Scope),
		"requires_engagement":    c.RequiresEngagement,
		"destructive":            c.Destructive,
		"open_world":             c.OpenWorld,
		"idempotent":             c.Idempotent,
		"returns_target_content": c.ReturnsTargetContent,
		"error_codes":            codes,
	}
}

// ContractMeta adapts ToolContract to pkg/errors.ContractMeta for result envelopes.
func (c ToolContract) ContractMeta() ocerrors.ContractMeta {
	return ocerrors.ContractMeta{
		Name:                  c.Name,
		ReturnsTargetContent:  c.ReturnsTargetContent,
		ProvenanceSource:      c.ProvenanceSource(),
		ContractSchemaVersion: ContractSchemaVersion,
	}
}

// HasErrorCode reports whether code is declared in the contract's error_codes.
func (c ToolContract) HasErrorCode(code string) bool {
	for _, declared := range c.ErrorCodes {
		if declared == code {
			return true
		}
	}
	return false
}

func sortedEffectStrings(effects []Effect) []string {
	if len(effects) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(effects))
	out := make([]string, 0, len(effects))
	for _, eff := range effects {
		s := string(eff)
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// NetworkCategories lists executable categories that imply network side effects.
var NetworkCategories = map[string]bool{
	"automotive":          true,
	"cloud_container_iac": true,
	"credentials":         true,
	"enumeration":         true,
	"exploitation":        true,
	"gps":                 true,
	"ir":                  true,
	"mobile":              true,
	"network":             true,
	"web":                 true,
	"wireless":            true,
	"wireless_attack":     true,
}

// DeviceCategories lists executable categories that imply physical device side effects.
var DeviceCategories = map[string]bool{
	"automotive":      true,
	"embedded":        true,
	"gps":             true,
	"nfc_rfid":        true,
	"rf":              true,
	"usb":             true,
	"wireless":        true,
	"wireless_attack": true,
}

// HardwareCategories lists physical-layer categories whose device readiness is tracked separately.
var HardwareCategories = map[string]bool{
	"rf":              true,
	"wireless_attack": true,
	"nfc_rfid":        true,
	"usb":             true,
	"embedded":        true,
	"automotive":      true,
	"gps":             true,
	"ir":              true,
}

// ContractFor returns the ToolContract for a registered tool name, or an unknown_tool *Error.
func ContractFor(name string) (*ToolContract, error) {
	return Default().Contract(name)
}

// ValidateAdvertised fails if any advertised tool name has no declared contract in Default().
func ValidateAdvertised(advertised []string) error {
	return Default().ValidateAdvertised(advertised)
}

// ValidateArguments validates args against the named tool's declared JSON Schema input_schema.
func ValidateArguments(toolName string, args map[string]any) error {
	return Default().ValidateArguments(toolName, args)
}

// ValidateArguments checks a call's argument map against this entry's input_schema.
// Missing required parameters return missing_parameter; unknown parameters or
// type/constraint mismatches return invalid_argument.
func (e *ToolEntry) ValidateArguments(args map[string]any) error {
	if e == nil {
		return ocerrors.New(ocerrors.CodeUnknownTool, "tool entry is nil")
	}
	schema := e.InputSchema
	if len(schema) == 0 {
		return nil
	}
	props, _ := schema["properties"].(map[string]any)
	required := stringSlice(schema["required"])

	// 1. Verify required parameters are present (and non-nil unless schema allows null).
	for _, reqName := range required {
		val, present := args[reqName]
		if !present {
			return ocerrors.New(
				ocerrors.CodeMissingParameter,
				fmt.Sprintf("tool %s requires parameter %q", e.Name, reqName),
				ocerrors.WithDetails(map[string]any{"tool": e.Name, "parameter": reqName}),
			)
		}
		if val == nil {
			if propSchema, ok := props[reqName].(map[string]any); ok && !schemaAllowsNull(propSchema) {
				return ocerrors.New(
					ocerrors.CodeMissingParameter,
					fmt.Sprintf("tool %s requires non-null parameter %q", e.Name, reqName),
					ocerrors.WithDetails(map[string]any{"tool": e.Name, "parameter": reqName}),
				)
			}
		}
	}

	// 2. Reject unknown parameters (fail closed on typos or undocumented arguments).
	allowExtra := false
	if ap, ok := schema["additionalProperties"].(bool); ok {
		allowExtra = ap
	}
	if !allowExtra && len(args) > 0 {
		var unknown []string
		for k := range args {
			if _, ok := props[k]; !ok {
				unknown = append(unknown, k)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return ocerrors.New(
				ocerrors.CodeInvalidArgument,
				fmt.Sprintf("tool %s received unknown parameter(s): %s", e.Name, strings.Join(unknown, ", ")),
				ocerrors.WithDetails(map[string]any{"tool": e.Name, "unknown_parameters": unknown}),
			)
		}
	}

	// 3. Validate each supplied parameter value against its property schema.
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		propSchema, ok := props[k].(map[string]any)
		if !ok {
			continue
		}
		if err := validateValueAgainstSchema(e.Name, k, args[k], propSchema); err != nil {
			return err
		}
	}
	return nil
}

func validateValueAgainstSchema(tool, path string, val any, schema map[string]any) error {
	if len(schema) == 0 {
		return nil
	}
	if anyOfRaw, ok := schema["anyOf"].([]any); ok && len(anyOfRaw) > 0 {
		for _, sub := range anyOfRaw {
			if subMap, ok := sub.(map[string]any); ok {
				if validateValueAgainstSchema(tool, path, val, subMap) == nil {
					return nil
				}
			}
		}
		return ocerrors.New(
			ocerrors.CodeInvalidArgument,
			fmt.Sprintf("tool %s parameter %q does not match any allowed type", tool, path),
			ocerrors.WithDetails(map[string]any{"tool": tool, "parameter": path}),
		)
	}

	if enumRaw, ok := schema["enum"].([]any); ok && len(enumRaw) > 0 {
		matched := false
		for _, allowed := range enumRaw {
			if fmt.Sprint(allowed) == fmt.Sprint(val) {
				matched = true
				break
			}
		}
		if !matched {
			return ocerrors.New(
				ocerrors.CodeInvalidArgument,
				fmt.Sprintf("tool %s parameter %q has disallowed value %v", tool, path, val),
				ocerrors.WithDetails(map[string]any{"tool": tool, "parameter": path}),
			)
		}
	}

	expectedType, hasType := schema["type"].(string)
	if !hasType {
		return nil
	}

	switch expectedType {
	case "null":
		if val != nil {
			return typeMismatch(tool, path, "null", val)
		}
	case "string":
		if _, ok := val.(string); !ok {
			return typeMismatch(tool, path, "string", val)
		}
	case "boolean":
		if _, ok := val.(bool); !ok {
			return typeMismatch(tool, path, "boolean", val)
		}
	case "integer":
		if !isJSONInteger(val) {
			return typeMismatch(tool, path, "integer", val)
		}
	case "number":
		if !isJSONNumber(val) {
			return typeMismatch(tool, path, "number", val)
		}
	case "array":
		elems, ok := toAnySlice(val)
		if !ok {
			return typeMismatch(tool, path, "array", val)
		}
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for i, elem := range elems {
				if err := validateValueAgainstSchema(tool, fmt.Sprintf("%s[%d]", path, i), elem, itemSchema); err != nil {
					return err
				}
			}
		}
	case "object":
		m, ok := toStringAnyMap(val)
		if !ok {
			return typeMismatch(tool, path, "object", val)
		}
		if apSchema, ok := schema["additionalProperties"].(map[string]any); ok {
			for k, v := range m {
				if err := validateValueAgainstSchema(tool, path+"."+k, v, apSchema); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func typeMismatch(tool, path, expected string, got any) error {
	return ocerrors.New(
		ocerrors.CodeInvalidArgument,
		fmt.Sprintf("tool %s parameter %q must be %s, got %T", tool, path, expected, got),
		ocerrors.WithDetails(map[string]any{"tool": tool, "parameter": path, "expected_type": expected}),
	)
}

func schemaAllowsNull(schema map[string]any) bool {
	if t, ok := schema["type"].(string); ok && t == "null" {
		return true
	}
	if anyOfRaw, ok := schema["anyOf"].([]any); ok {
		for _, sub := range anyOfRaw {
			if subMap, ok := sub.(map[string]any); ok && schemaAllowsNull(subMap) {
				return true
			}
		}
	}
	return false
}

func isJSONInteger(v any) bool {
	switch n := v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float64:
		return !math.IsNaN(n) && !math.IsInf(n, 0) && math.Trunc(n) == n
	case float32:
		f := float64(n)
		return !math.IsNaN(f) && !math.IsInf(f, 0) && math.Trunc(f) == f
	case json.Number:
		_, err := n.Int64()
		return err == nil
	default:
		return false
	}
}

func isJSONNumber(v any) bool {
	switch n := v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float64:
		return !math.IsNaN(n) && !math.IsInf(n, 0)
	case float32:
		f := float64(n)
		return !math.IsNaN(f) && !math.IsInf(f, 0)
	case json.Number:
		f, err := n.Float64()
		return err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return false
	}
}

func toAnySlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	case []int:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	case []float64:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	case []map[string]any:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	default:
		return nil, false
	}
}

func toStringAnyMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		if m == nil {
			return nil, false
		}
		return m, true
	case map[string]string:
		if m == nil {
			return nil, false
		}
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[k] = val
		}
		return out, true
	default:
		return nil, false
	}
}

func stringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
