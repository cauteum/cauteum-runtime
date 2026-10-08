// SPDX-FileCopyrightText: Copyright (c) 2026 cauteum
// SPDX-License-Identifier: Apache-2.0

package agentconfig

import (
	"os"
	"path/filepath"
)

// Options controls installation of the supervisor-owned policy guidance.
// Agent and harness configuration stays in the sandbox image/workspace, as in OpenShell.
type Options struct{}

// Staged is a host-side tree ready to copy into the guest.
type Staged struct {
	Dir           string
	EtcOSGHost    string
	SkillsHostDir string
}

// Stage prepares only the built-in supervisor guidance; it does not parse or
// translate any agent-specific manifest.
func Stage(_ Options) (Staged, error) {
	root, err := os.MkdirTemp("", "cauteum-supervisor-guidance-*")
	if err != nil {
		return Staged{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(root)
		}
	}()
	skillsDir := filepath.Join(root, "cauteum", "skills")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		return Staged{}, err
	}
	if err := writeBuiltinSkills(skillsDir); err != nil {
		return Staged{}, err
	}
	agentsPath := filepath.Join(root, "cauteum", agentsMDName)
	if err := os.WriteFile(agentsPath, []byte(agentsMDBody), 0o444); err != nil {
		return Staged{}, err
	}
	cleanup = false
	return Staged{
		Dir:           root,
		EtcOSGHost:    filepath.Join(root, "cauteum"),
		SkillsHostDir: skillsDir,
	}, nil
}

// DefaultOptions returns the supervisor guidance configuration.
func DefaultOptions() Options { return Options{} }

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
