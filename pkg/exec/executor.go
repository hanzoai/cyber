package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"strings"
	"sync"
	"time"
)

// ScrubbedEnvPrefixes lists environment prefixes stripped from child tool processes
// so they cannot inherit signing or approval keys.
var ScrubbedEnvPrefixes = []string{
	"OPENCYBER_APPROVAL_KEY",
}

// ValidateArguments verifies that no argument contains a NUL byte.
func ValidateArguments(args []string) error {
	for i, arg := range args {
		if strings.ContainsRune(arg, '\x00') {
			return NewError("invalid_argument", "arguments cannot contain NUL bytes",
				WithDetails(map[string]any{"index": i}))
		}
	}
	return nil
}

// BuildEnvironment copies os.Environ(), scrubs sensitive prefixes, and applies validated overrides.
func BuildEnvironment(overrides map[string]string) ([]string, error) {
	envMap := make(map[string]string)
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		scrubbed := false
		for _, pfx := range ScrubbedEnvPrefixes {
			if strings.HasPrefix(k, pfx) {
				scrubbed = true
				break
			}
		}
		if !scrubbed {
			envMap[k] = v
		}
	}
	for k, v := range overrides {
		if k == "" || strings.ContainsAny(k, "=\x00") {
			return nil, NewError("invalid_argument", "environment names must be non-empty strings without '=' or NUL")
		}
		if strings.ContainsRune(v, '\x00') {
			return nil, NewError("invalid_argument", "environment values must not contain NUL bytes")
		}
		envMap[k] = v
	}
	keys := sortedMapKeys(envMap)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+envMap[k])
	}
	return out, nil
}

// ExecutableStatus reports whether executable is resolved on PATH.
func ExecutableStatus(executable string) ToolAvailability {
	resolved, err := osexec.LookPath(executable)
	if err != nil {
		return ToolAvailability{
			Name:       executable,
			Executable: executable,
			Available:  false,
			Required:   true,
		}
	}
	return ToolAvailability{
		Name:       executable,
		Executable: executable,
		Available:  true,
		Path:       resolved,
		Required:   true,
	}
}

// PreflightDecision allows callers (e.g., the PoC engine) to provide a stricter
// pre-audited scope decision without weakening the offline check.
type PreflightDecision struct {
	Candidates []string `json:"candidates"`
	Source     string   `json:"source"`
}

// ExecRequest specifies one direct executable invocation.
type ExecRequest struct {
	Executable       string             `json:"executable"`
	Arguments        []string           `json:"arguments"`
	EngagementID     string             `json:"engagement_id"`
	WorkingDirectory string             `json:"working_directory,omitempty"`
	Stdin            string             `json:"stdin,omitempty"`
	Environment      map[string]string  `json:"environment,omitempty"`
	Preflight        *PreflightDecision `json:"preflight,omitempty"`
	TimeoutOverride  *time.Duration     `json:"-"`
	MaxOutputBytes   *int64             `json:"-"`
}

// ExecResult is the structured execution outcome matching executor.py.
type ExecResult struct {
	OK                  bool              `json:"ok"`
	Success             bool              `json:"success"`
	EngagementID        string            `json:"engagement_id"`
	Executable          string            `json:"executable"`
	OCTool              string            `json:"oc_tool,omitempty"`
	Category            string            `json:"category,omitempty"`
	ScriptOrigin        string            `json:"script_origin,omitempty"`
	Backend             string            `json:"backend,omitempty"`
	SandboxID           string            `json:"sandbox_id,omitempty"`
	Available           bool              `json:"available"`
	Optional            bool              `json:"optional,omitempty"`
	MissingDependencies []string          `json:"missing_dependencies,omitempty"`
	Argv                []string          `json:"argv,omitempty"`
	Cwd                 string            `json:"cwd,omitempty"`
	ReturnCode          *int              `json:"returncode,omitempty"`
	Stdout              string            `json:"stdout,omitempty"`
	Stderr              string            `json:"stderr,omitempty"`
	StdoutBytes         int64             `json:"stdout_bytes"`
	StderrBytes         int64             `json:"stderr_bytes"`
	Truncated           bool              `json:"truncated"`
	TimedOut            bool              `json:"timed_out"`
	TimeoutS            float64           `json:"timeout_s,omitempty"`
	MaxOutputBytes      int64             `json:"max_output_bytes,omitempty"`
	DurationMS          float64           `json:"duration_ms"`
	ScopeEnforced       bool              `json:"scope_enforced"`
	AuditSeq            *int64            `json:"audit_seq,omitempty"`
	Error               *Error            `json:"error,omitempty"`
	ErrorMessage        string            `json:"error_message,omitempty"`
	Coverage            *Coverage         `json:"coverage,omitempty"`
	Limitations         []string          `json:"limitations,omitempty"`
	Limit               *LimitFacts       `json:"limit,omitempty"`
	Metadata            map[string]any    `json:"metadata,omitempty"`
}

// Executor runs direct subprocesses without a shell, enforcing engagement cwd,
// scope, offline policy, deadlines, output caps, and audit recording.
type Executor struct {
	Resolver      EngagementResolver
	Scope         ScopeValidator
	Catalog       CatalogLookup
	Audit         AuditRecorder
	AuditEnabled  *bool
	AuditRequired *bool
}

// NewExecutor constructs an Executor with sensible defaults for Scope and Audit.
func NewExecutor(resolver EngagementResolver, audit AuditRecorder) *Executor {
	if audit == nil {
		audit = NopAuditRecorder{}
	}
	return &Executor{
		Resolver: resolver,
		Scope:    &DefaultScopeValidator{Resolver: resolver},
		Audit:    audit,
	}
}

func (e *Executor) auditEnabled() bool {
	if e.AuditEnabled != nil {
		return *e.AuditEnabled
	}
	raw := strings.TrimSpace(os.Getenv("OPENCYBER_AUDIT"))
	if raw == "" {
		return true
	}
	return isTruthy(raw)
}

func (e *Executor) auditRequired() bool {
	if e.AuditRequired != nil {
		return *e.AuditRequired
	}
	return isTruthy(os.Getenv("OPENCYBER_AUDIT_REQUIRED"))
}

func (e *Executor) recordAudit(engagementID string, event map[string]any) (*int64, error) {
	if !e.auditEnabled() || e.Audit == nil {
		return nil, nil
	}
	seq, err := e.Audit.Record(engagementID, event)
	if err != nil {
		if e.auditRequired() {
			return nil, err
		}
		return nil, nil
	}
	if seq > 0 {
		return &seq, nil
	}
	return nil, nil
}

func (e *Executor) scopeValidator() ScopeValidator {
	if e.Scope != nil {
		return e.Scope
	}
	return &DefaultScopeValidator{Resolver: e.Resolver}
}

// ExecuteTool runs a binary directly (no shell) under named timeout & output caps.
func (e *Executor) ExecuteTool(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	if e.Resolver == nil {
		return nil, NewError("internal_error", "executor has no engagement resolver configured")
	}
	if strings.TrimSpace(req.Executable) == "" {
		return nil, NewError("invalid_argument", "executable must not be empty")
	}
	workDir := req.WorkingDirectory
	if workDir == "" {
		workDir = "."
	}
	cwd, err := e.Resolver.ResolvePath(req.EngagementID, workDir, true)
	if err != nil {
		return nil, err
	}
	if err := ValidateArguments(req.Arguments); err != nil {
		return nil, err
	}

	started := time.Now()
	startedAt := nowUTC()
	sv := e.scopeValidator()

	var scopeDec ScopeDecision
	if req.Preflight != nil {
		source := req.Preflight.Source
		if source == "" {
			source = "poc_preflight"
		}
		scopeDec = ScopeDecision{
			Enforced:   true,
			Allowed:    true,
			Candidates: append([]string(nil), req.Preflight.Candidates...),
			Source:     source,
		}
		if _, aerr := e.recordAudit(req.EngagementID, map[string]any{
			"event":      "tool.scope_checked",
			"executable": req.Executable,
			"arguments":  req.Arguments,
			"candidates": scopeDec.Candidates,
			"allowed":    true,
			"source":     source,
			"ts":         startedAt,
		}); aerr != nil {
			return nil, aerr
		}
	} else {
		scopeDec, err = sv.CheckCommand(req.EngagementID, req.Executable, req.Arguments)
		if err != nil {
			_, _ = e.recordAudit(req.EngagementID, map[string]any{
				"event":             "tool.denied",
				"executable":        req.Executable,
				"arguments":         req.Arguments,
				"working_directory": workDir,
				"reason":            err.Error(),
				"ts":                startedAt,
			})
			return nil, err
		}
		if scopeDec.Enforced {
			if _, aerr := e.recordAudit(req.EngagementID, map[string]any{
				"event":      "tool.scope_checked",
				"executable": req.Executable,
				"arguments":  req.Arguments,
				"candidates": scopeDec.Candidates,
				"allowed":    scopeDec.Allowed,
				"ts":         startedAt,
			}); aerr != nil {
				return nil, aerr
			}
		}
	}

	off := sv.CheckOffline(req.Executable)
	if off.Blocked {
		_, _ = e.recordAudit(req.EngagementID, map[string]any{
			"event":             "tool.denied",
			"executable":        req.Executable,
			"arguments":         req.Arguments,
			"working_directory": workDir,
			"reason":            off.Reason,
			"ts":                startedAt,
		})
		return nil, NewError("offline_blocked", off.Reason, WithDetails(map[string]any{"executable": req.Executable}))
	}

	finish := func(res *ExecResult, eventName string) (*ExecResult, error) {
		res.DurationMS = float64(time.Since(started).Microseconds()) / 1000.0
		res.ScopeEnforced = scopeDec.Enforced
		if res.Backend == "" {
			res.Backend = "local"
		}
		seq, aerr := e.recordAudit(req.EngagementID, map[string]any{
			"event":             eventName,
			"executable":        req.Executable,
			"arguments":         req.Arguments,
			"working_directory": workDir,
			"cwd":               cwd,
			"started_at":        startedAt,
			"duration_ms":       res.DurationMS,
			"ok":                res.OK,
			"success":           res.Success,
			"returncode":        res.ReturnCode,
			"stdout_bytes":      res.StdoutBytes,
			"stderr_bytes":      res.StderrBytes,
			"stdin_bytes":       len(req.Stdin),
			"truncated":         res.Truncated,
			"timed_out":         res.TimedOut,
			"error":             res.ErrorMessage,
		})
		if aerr != nil {
			return nil, aerr
		}
		res.AuditSeq = seq
		return res, nil
	}

	// Resolve availability via catalog if present, otherwise PATH.
	var avail ToolAvailability
	var inCatalog bool
	if e.Catalog != nil {
		avail, inCatalog = e.Catalog.LookupExecutable(req.Executable)
	}
	if !inCatalog {
		avail = ExecutableStatus(req.Executable)
	}
	if !avail.Available || avail.Path == "" {
		optional := inCatalog && !avail.Required
		msg := fmt.Sprintf("executable is not installed: %s", req.Executable)
		if optional && avail.OptionalReason != "" {
			missing := req.Executable
			if avail.Path != "" && len(avail.MissingDependencies) > 0 {
				missing = strings.Join(avail.MissingDependencies, ", ")
			}
			msg = fmt.Sprintf("integration unavailable: %s; %s Missing: %s.", req.Executable, avail.OptionalReason, missing)
		} else if avail.Path != "" && len(avail.MissingDependencies) > 0 {
			msg = fmt.Sprintf("integration unavailable: %s; missing dependencies: %s", req.Executable, strings.Join(avail.MissingDependencies, ", "))
		}
		ocErr := NewError("integration_unavailable", msg, WithDetails(map[string]any{
			"executable":           req.Executable,
			"optional":             optional,
			"missing_dependencies": avail.MissingDependencies,
		}))
		return finish(&ExecResult{
			OK:                  false,
			Success:             false,
			EngagementID:        req.EngagementID,
			Executable:          req.Executable,
			Available:           false,
			Optional:            optional,
			MissingDependencies: avail.MissingDependencies,
			Cwd:                 cwd,
			Error:               ocErr,
			ErrorMessage:        msg,
			Limitations:         []string{"The tool did not run."},
		}, "tool.exec")
	}

	// Validate limits and environment before spawning.
	var timeoutS float64
	if req.TimeoutOverride != nil {
		timeoutS = req.TimeoutOverride.Seconds()
		if timeoutS < 0 {
			return nil, NewError("invalid_argument", "timeout must be non-negative")
		}
	} else {
		timeoutS, err = LimitToolTimeout.Effective()
		if err != nil {
			return nil, err
		}
	}
	var outputCap int64
	if req.MaxOutputBytes != nil {
		outputCap = *req.MaxOutputBytes
		if outputCap < 0 {
			return nil, NewError("invalid_argument", "max_output_bytes must be non-negative")
		}
	} else {
		capF, cerr := LimitToolMaxOutput.Effective()
		if cerr != nil {
			return nil, cerr
		}
		outputCap = int64(capF)
	}

	env, err := BuildEnvironment(req.Environment)
	if err != nil {
		return nil, err
	}

	argv := append([]string{avail.Path}, req.Arguments...)
	cmd := osexec.Command(avail.Path, req.Arguments...)
	cmd.Dir = cwd
	cmd.Env = env
	configureProcessGroup(cmd)

	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		ocErr := NewError("execution_failed", err.Error(), WithDetails(map[string]any{
			"executable": req.Executable,
			"argv":       argv,
		}), WithCause(err))
		return finish(&ExecResult{
			OK:           false,
			Success:      false,
			EngagementID: req.EngagementID,
			Executable:   req.Executable,
			Available:    true,
			Argv:         argv,
			Cwd:          cwd,
			Error:        ocErr,
			ErrorMessage: err.Error(),
			Limitations:  []string{"The process did not start."},
		}, "tool.exec")
	}

	outReader := newCappedDrain(outputCap)
	errReader := newCappedDrain(outputCap)

	var drainWG sync.WaitGroup
	drainWG.Add(2)
	go func() {
		defer drainWG.Done()
		outReader.drain(stdoutPipe)
	}()
	go func() {
		defer drainWG.Done()
		errReader.drain(stderrPipe)
	}()

	waitDone := make(chan error, 1)
	go func() {
		drainWG.Wait()
		waitDone <- cmd.Wait()
	}()

	var timerCh <-chan time.Time
	var timer *time.Timer
	if timeoutS > 0 {
		timer = time.NewTimer(time.Duration(timeoutS * float64(time.Second)))
		defer timer.Stop()
		timerCh = timer.C
	}

	var waitErr error
	timedOut := false
	cancelled := false

	select {
	case waitErr = <-waitDone:
	case <-timerCh:
		timedOut = true
		terminateProcessGroup(cmd, waitDone)
	case <-ctx.Done():
		cancelled = true
		terminateProcessGroup(cmd, waitDone)
	}

	if cancelled {
		_, _ = e.recordAudit(req.EngagementID, map[string]any{
			"event":             "tool.cancelled",
			"executable":        req.Executable,
			"arguments":         req.Arguments,
			"working_directory": workDir,
			"cwd":               cwd,
			"started_at":        startedAt,
			"duration_ms":       float64(time.Since(started).Microseconds()) / 1000.0,
		})
		return nil, NewError("cancelled", fmt.Sprintf("%s cancelled: %v", req.Executable, ctx.Err()), WithCause(ctx.Err()))
	}

	exitCode := 0
	if waitErr != nil {
		var exitErr *osexec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if !timedOut {
			exitCode = -1
		}
	}
	if timedOut && cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	truncated := outReader.truncated || errReader.truncated
	res := &ExecResult{
		OK:             !timedOut,
		Success:        exitCode == 0 && !timedOut,
		EngagementID:   req.EngagementID,
		Executable:     req.Executable,
		Available:      true,
		Argv:           argv,
		Cwd:            cwd,
		ReturnCode:     intPtr(exitCode),
		Stdout:         outReader.String(),
		Stderr:         errReader.String(),
		StdoutBytes:    outReader.received,
		StderrBytes:    errReader.received,
		Truncated:      truncated,
		TimedOut:       timedOut,
		TimeoutS:       timeoutS,
		MaxOutputBytes: outputCap,
	}

	if timedOut {
		msg := fmt.Sprintf("%s exceeded the %g-second server deadline and was stopped", req.Executable, timeoutS)
		ocErr := NewError("timed_out", msg,
			WithDetails(map[string]any{"executable": req.Executable, "timeout_s": timeoutS}),
			WithLimit(LimitToolTimeout.Facts(timeoutS, nil, "")),
		)
		res.OK = false
		res.Success = false
		res.Error = ocErr
		res.ErrorMessage = msg
		res.Coverage = &Coverage{Status: "partial", Exhausted: boolPtr(false)}
		res.Limitations = []string{
			"The run stopped at the server deadline. Output captured so far is included; the run is incomplete.",
		}
	} else if truncated {
		res.Coverage = &Coverage{Status: "partial", Exhausted: boolPtr(false)}
		res.Limitations = []string{
			fmt.Sprintf("Output was capped at %d bytes per stream; bytes beyond the cap were read and discarded.", outputCap),
		}
		res.Limit = LimitToolMaxOutput.Facts(float64(outputCap), nil, "")
	}

	return finish(res, "tool.exec")
}

// ExecuteBash executes a bash script under engagement scope/audit rules (`oc_bash`).
func (e *Executor) ExecuteBash(ctx context.Context, engagementID, script, workingDir, stdin string, env map[string]string) (*ExecResult, error) {
	if script == "" {
		return nil, NewError("invalid_argument", "script must not be empty")
	}
	res, err := e.ExecuteTool(ctx, ExecRequest{
		Executable:       "bash",
		Arguments:        []string{"-c", script},
		EngagementID:     engagementID,
		WorkingDirectory: workingDir,
		Stdin:            stdin,
		Environment:      env,
	})
	if err != nil {
		return nil, err
	}
	res.OCTool = "oc_bash"
	res.Category = "execution"
	return res, nil
}

// ExecutePython executes inline Python source or an engagement-scoped .py file (`oc_python`).
func (e *Executor) ExecutePython(ctx context.Context, engagementID, source, scriptPath string, scriptArgs []string, workingDir, stdin string, env map[string]string) (*ExecResult, error) {
	hasSource := source != ""
	hasPath := scriptPath != ""
	if hasSource == hasPath {
		return nil, NewError("invalid_argument", "provide exactly one of source or path")
	}
	var args []string
	var origin string
	if hasSource {
		args = append([]string{"-c", source}, scriptArgs...)
		origin = "inline"
	} else {
		resolved, err := e.Resolver.ResolvePath(engagementID, scriptPath, true)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(resolved)
		if err != nil || !fi.Mode().IsRegular() {
			return nil, NewError("invalid_argument", fmt.Sprintf("not a Python file: %s", scriptPath))
		}
		args = append([]string{resolved}, scriptArgs...)
		origin = resolved
	}
	res, err := e.ExecuteTool(ctx, ExecRequest{
		Executable:       "python3",
		Arguments:        args,
		EngagementID:     engagementID,
		WorkingDirectory: workingDir,
		Stdin:            stdin,
		Environment:      env,
	})
	if err != nil {
		return nil, err
	}
	res.OCTool = "oc_python"
	res.Category = "execution"
	res.ScriptOrigin = origin
	return res, nil
}

type cappedDrain struct {
	cap       int64
	buf       bytes.Buffer
	received  int64
	truncated bool
}

func newCappedDrain(capBytes int64) *cappedDrain {
	return &cappedDrain{cap: capBytes}
}

func (c *cappedDrain) drain(r io.Reader) {
	chunk := make([]byte, 32*1024)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			data := chunk[:n]
			c.received += int64(n)
			if c.cap == 0 {
				_, _ = c.buf.Write(data)
			} else {
				room := c.cap - int64(c.buf.Len())
				if room <= 0 {
					c.truncated = true
				} else if int64(n) > room {
					c.truncated = true
					_, _ = c.buf.Write(data[:room])
				} else {
					_, _ = c.buf.Write(data)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (c *cappedDrain) String() string {
	return c.buf.String()
}
