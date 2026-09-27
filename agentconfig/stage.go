// SPDX-FileCopyrightText: Copyright (c) 2026 whaleshell
// SPDX-License-Identifier: MIT

package agentconfig

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is an optional host-side agent-config.yaml (MIT).
// Paths are resolved relative to the manifest file directory.
type Manifest struct {
	Version        int         `yaml:"version"`
	Skills         []string    `yaml:"skills,omitempty"`
	MCP            ManifestMCP `yaml:"mcp,omitempty"`
	Home           []HomeSeed  `yaml:"home,omitempty"`
	AgentsMD       *bool       `yaml:"agents_md,omitempty"`
	Payload        []string    `yaml:"payload,omitempty"`
	PromptTemplate string      `yaml:"prompt_template,omitempty"`
	Harness        string      `yaml:"harness,omitempty"`
	RuntimeMode    string      `yaml:"runtime_mode,omitempty"`
	IncludeRuntime *bool       `yaml:"include_runtime,omitempty"`
	// CursorCLIConfig is a host path to cli-config.json (attribution, permissions, …).
	CursorCLIConfig string `yaml:"cursor_cli_config,omitempty"`
	// SeedCursorCLI writes/merges default cli-config (attribution off). Default true.
	SeedCursorCLI *bool `yaml:"seed_cursor_cli,omitempty"`
}

// ManifestMCP seeds MCP client config into guest HOME.
type ManifestMCP struct {
	Cursor string `yaml:"cursor,omitempty"`
	Claude string `yaml:"claude,omitempty"`
}

// HomeSeed copies a host path under GuestHome.
type HomeSeed struct {
	Src  string `yaml:"src"`
	Dest string `yaml:"dest"`
}

// Options control staging for one sandbox create.
type Options struct {
	ManifestPath   string
	SkillPaths     []string
	MCPCursor      string
	MCPClaude      string
	IncludeBuiltin bool
	WriteAgentsMD  bool
	// IncludeRuntime ships supervisor + harness adapters into agent-payload.
	IncludeRuntime bool
	Harness        string // cursor|claude
	RuntimeMode    string // once|watch
	PromptFile     string // host path → agent-prompt.md
	// CursorCLIConfig is host path to ~/.cursor/cli-config.json content.
	CursorCLIConfig string
	// SeedCursorCLI installs builtin cli-config (attribution off). Default true.
	SeedCursorCLI bool
}

// Staged is a host temp tree ready to CopyTo into the guest.
type Staged struct {
	Dir string

	EtcOSGHost     string
	SkillsHostDir  string
	PayloadHostDir string
	HomeSeeds      []StagedHome
	AgentsMDHost   string
	MCPCursorHost  string
	MCPClaudeHost  string
	CLIConfigHost  string // → $HOME/.cursor/cli-config.json
	Harness        string
	RuntimeMode    string
}

// StagedHome is one HOME-relative install.
type StagedHome struct {
	HostSrc string
	RelDest string
}

// LoadManifest reads and validates agent-config.yaml.
func LoadManifest(path string) (Manifest, string, error) {
	path = filepath.Clean(path)
	b, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, "", err
	}
	var m Manifest
	if err := yaml.Unmarshal(b, &m); err != nil {
		return Manifest{}, "", fmt.Errorf("agent-config: parse %s: %w", path, err)
	}
	return m, filepath.Dir(path), nil
}

// Stage builds a host directory tree for injection.
func Stage(opt Options) (Staged, error) {
	root, err := os.MkdirTemp("", "whaleshell-agentconfig-*")
	if err != nil {
		return Staged{}, err
	}
	st := Staged{Dir: root}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(root)
		}
	}()

	skillsDir := filepath.Join(root, "whaleshell", "skills")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		return Staged{}, err
	}
	payloadDir := filepath.Join(root, "whaleshell", "agent-payload")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		return Staged{}, err
	}

	if opt.IncludeBuiltin {
		if err := writeBuiltinSkills(skillsDir); err != nil {
			return Staged{}, err
		}
	}

	wantRuntime := opt.IncludeRuntime
	harness := strings.TrimSpace(opt.Harness)
	mode := strings.TrimSpace(opt.RuntimeMode)
	promptSrc := strings.TrimSpace(opt.PromptFile)

	if strings.TrimSpace(opt.ManifestPath) != "" {
		man, manBase, err := LoadManifest(opt.ManifestPath)
		if err != nil {
			return Staged{}, err
		}
		for _, p := range man.Skills {
			if err := copySkillInto(skillsDir, resolvePath(manBase, p)); err != nil {
				return Staged{}, err
			}
		}
		for _, p := range man.Payload {
			src := resolvePath(manBase, p)
			if err := copyPathInto(payloadDir, src); err != nil {
				return Staged{}, fmt.Errorf("agent-config payload %s: %w", p, err)
			}
		}
		for _, h := range man.Home {
			src := resolvePath(manBase, h.Src)
			rel := filepath.ToSlash(strings.TrimSpace(h.Dest))
			if rel == "" {
				return Staged{}, fmt.Errorf("agent-config home entry missing dest")
			}
			if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") {
				return Staged{}, fmt.Errorf("agent-config home dest must be relative without ..: %q", rel)
			}
			if fi, err := os.Stat(src); err == nil && fi.IsDir() {
				if filepath.Base(src) != filepath.Base(rel) {
					return Staged{}, fmt.Errorf("agent-config home: directory src basename %q must match dest basename %q", filepath.Base(src), filepath.Base(rel))
				}
			}
			st.HomeSeeds = append(st.HomeSeeds, StagedHome{HostSrc: src, RelDest: rel})
		}
		if man.MCP.Cursor != "" {
			st.MCPCursorHost = resolvePath(manBase, man.MCP.Cursor)
		}
		if man.MCP.Claude != "" {
			st.MCPClaudeHost = resolvePath(manBase, man.MCP.Claude)
		}
		if man.AgentsMD != nil {
			opt.WriteAgentsMD = *man.AgentsMD
		}
		if man.Harness != "" {
			harness = man.Harness
		}
		if man.RuntimeMode != "" {
			mode = man.RuntimeMode
		}
		if man.PromptTemplate != "" {
			promptSrc = resolvePath(manBase, man.PromptTemplate)
		}
		if man.IncludeRuntime != nil {
			wantRuntime = *man.IncludeRuntime
		} else if harness != "" || promptSrc != "" {
			wantRuntime = true
		}
		if man.CursorCLIConfig != "" {
			opt.CursorCLIConfig = resolvePath(manBase, man.CursorCLIConfig)
		}
		if man.SeedCursorCLI != nil {
			opt.SeedCursorCLI = *man.SeedCursorCLI
		}
	}

	for _, p := range opt.SkillPaths {
		if err := copySkillInto(skillsDir, filepath.Clean(p)); err != nil {
			return Staged{}, err
		}
	}
	if c := strings.TrimSpace(opt.MCPCursor); c != "" {
		st.MCPCursorHost = filepath.Clean(c)
	}
	if c := strings.TrimSpace(opt.MCPClaude); c != "" {
		st.MCPClaudeHost = filepath.Clean(c)
	}
	if c := strings.TrimSpace(opt.CursorCLIConfig); c != "" {
		st.CLIConfigHost = filepath.Clean(c)
	} else if opt.SeedCursorCLI {
		// Will materialize into agent-payload below (OpenShell bake path).
		st.CLIConfigHost = "builtin"
	}

	if harness == "" {
		harness = "cursor"
	}
	if mode == "" {
		mode = "once"
	}
	st.Harness = harness
	st.RuntimeMode = mode

	// Ensure payload exists when we need cursor cli-config even without runtime.
	needPayload := wantRuntime || st.CLIConfigHost != ""
	if needPayload {
		if err := os.MkdirAll(payloadDir, 0o755); err != nil {
			return Staged{}, err
		}
	}

	if wantRuntime {
		if err := writeBuiltinRuntime(payloadDir); err != nil {
			return Staged{}, err
		}
		envSnippet := fmt.Sprintf("WHALESHELL_AGENT_HARNESS=%s\nWHALESHELL_AGENT_RUN_MODE=%s\n", harness, mode)
		if err := os.WriteFile(filepath.Join(payloadDir, "runtime.env"), []byte(envSnippet), 0o600); err != nil {
			return Staged{}, err
		}
	}

	// Bake cursor cli-config into agent-payload (canonical seed for harness prepare-home).
	if st.CLIConfigHost != "" {
		cursorDir := filepath.Join(payloadDir, "cursor")
		if err := os.MkdirAll(cursorDir, 0o755); err != nil {
			return Staged{}, err
		}
		dst := filepath.Join(cursorDir, "cli-config.json")
		if st.CLIConfigHost == "builtin" {
			b, err := builtinFS.ReadFile("cursor/cli-config.json")
			if err != nil {
				return Staged{}, err
			}
			if err := os.WriteFile(dst, b, 0o600); err != nil {
				return Staged{}, err
			}
		} else {
			if err := copyFile(st.CLIConfigHost, dst, 0o600); err != nil {
				return Staged{}, fmt.Errorf("cursor cli-config: %w", err)
			}
		}
		st.CLIConfigHost = dst // path inside staged tree; Install applies via prepare-home
	}

	if promptSrc != "" {
		b, err := os.ReadFile(promptSrc)
		if err != nil {
			return Staged{}, fmt.Errorf("agent-config prompt: %w", err)
		}
		if err := os.WriteFile(filepath.Join(payloadDir, "agent-prompt.md"), b, 0o444); err != nil {
			return Staged{}, err
		}
	} else if wantRuntime {
		def := "# whaleshell agent prompt\n\nSummarize the workspace and wait for operator instructions.\n"
		if err := os.WriteFile(filepath.Join(payloadDir, "agent-prompt.md"), []byte(def), 0o444); err != nil {
			return Staged{}, err
		}
	}

	st.SkillsHostDir = skillsDir
	st.EtcOSGHost = filepath.Join(root, "whaleshell")
	if n, _ := countEntries(payloadDir); n > 0 {
		st.PayloadHostDir = payloadDir
	} else {
		_ = os.Remove(payloadDir)
	}
	if opt.WriteAgentsMD {
		p := filepath.Join(root, agentsMDName)
		if err := os.WriteFile(p, []byte(agentsMDBody), 0o444); err != nil {
			return Staged{}, err
		}
		st.AgentsMDHost = p
	}

	cleanup = false
	return st, nil
}

func writeBuiltinSkills(skillsDir string) error {
	advisor := filepath.Join(skillsDir, "policy_advisor.md")
	b, err := builtinFS.ReadFile("skills/policy_advisor.md")
	if err != nil {
		return err
	}
	if err := os.WriteFile(advisor, b, 0o444); err != nil {
		return err
	}
	skillDir := filepath.Join(skillsDir, "policy-advisor")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return err
	}
	sb, err := builtinFS.ReadFile("skills/policy-advisor/SKILL.md")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(skillDir, "SKILL.md"), sb, 0o444)
}

func writeBuiltinRuntime(payloadDir string) error {
	for _, name := range runtimeFiles {
		b, err := builtinFS.ReadFile(name)
		if err != nil {
			return err
		}
		dst := filepath.Join(payloadDir, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o755)
		if strings.HasSuffix(name, ".md") {
			mode = 0o444
		}
		if err := os.WriteFile(dst, b, mode); err != nil {
			return err
		}
	}
	return nil
}

func resolvePath(base, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return p
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}

func copySkillInto(skillsDir, src string) error {
	st, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("skills %s: %w", src, err)
	}
	if st.IsDir() {
		return copyDir(src, filepath.Join(skillsDir, filepath.Base(src)))
	}
	base := filepath.Base(src)
	if strings.EqualFold(base, "SKILL.md") {
		name := filepath.Base(filepath.Dir(src))
		if name == "" || name == "." || name == "/" {
			name = "skill"
		}
		dstDir := filepath.Join(skillsDir, name)
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			return err
		}
		return copyFile(src, filepath.Join(dstDir, "SKILL.md"), 0o444)
	}
	dstDir := filepath.Join(skillsDir, strings.TrimSuffix(base, filepath.Ext(base)))
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	return copyFile(src, filepath.Join(dstDir, "SKILL.md"), 0o444)
}

func copyPathInto(dstDir, src string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	name := filepath.Base(src)
	if st.IsDir() {
		return copyDir(src, filepath.Join(dstDir, name))
	}
	return copyFile(src, filepath.Join(dstDir, name), 0o644)
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		return copyFile(path, target, mode)
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func countEntries(dir string) (int, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	return len(ents), nil
}
