// SPDX-FileCopyrightText: Copyright (c) 2026 cauteum
// SPDX-License-Identifier: Apache-2.0

package agentconfig

import "embed"

//go:embed skills/policy_advisor.md skills/policy-advisor/SKILL.md
var builtinFS embed.FS

const agentsMDName = "AGENTS.md"

// agentsMDBody is written to /AGENTS.md when missing.
const agentsMDBody = "" +
	"# cauteum Sandbox Guidance\n" +
	"\n" +
	"When you see a policy deny / CONNECT 403, do not treat it as final if the user\n" +
	"task still needs that request. Read `/etc/cauteum/skills/policy_advisor.md`\n" +
	"and use the `policy-advisor` skill, then ask the operator to apply the\n" +
	"narrowest change (`cauteum policy set` / provider attach) before retrying.\n" +
	"\n" +
	"## Git / commits\n" +
	"\n" +
	"Do **not** add Cursor co-authorship or trailers (Co-authored-by: Cursor,\n" +
	"Made-with: Cursor, Made with Cursor, --trailer). Commit messages must be\n" +
	"plain subject/body only.\n"
