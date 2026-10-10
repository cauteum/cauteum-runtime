// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package agentconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageContainsOnlySupervisorGuidance(t *testing.T) {
	st, err := Stage(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(st.Dir)
	for _, rel := range []string{"policy_advisor.md", "policy-advisor/SKILL.md"} {
		if _, err := os.Stat(filepath.Join(st.SkillsHostDir, rel)); err != nil {
			t.Fatalf("missing supervisor skill %s: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(st.EtcOSGHost, "agent-payload")); !os.IsNotExist(err) {
		t.Fatalf("legacy agent payload should not be staged, stat error=%v", err)
	}
	b, err := os.ReadFile(filepath.Join(st.EtcOSGHost, agentsMDName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "agent-payload") || !strings.Contains(string(b), "policy-advisor") {
		t.Fatalf("unexpected AGENTS.md guidance: %s", b)
	}
}
