# SPDX-FileCopyrightText: Copyright (c) 2026 whaleshell
# SPDX-License-Identifier: Apache-2.0

# whaleshell Policy Advisor

Use this when the sandbox proxy blocks a network request (CONNECT 403 /
`policy_denied`, or deny lines in `whaleshell logs`).

## Goal

Draft the **smallest** policy change that unblocks the user's current task.
The operator approves; do not bypass the proxy.

## Local API — `http://policy.local`

- `GET /v1/policy/current` — current effective policy (YAML).
- `GET /v1/denials?last=10` — recent deny/reject OCSF lines (newest first).
- `POST /v1/proposals` — submit a proposal (`intent_summary` + `addRule` ops).
  Response `202` includes `accepted_chunk_ids` and `rejection_reasons`.
- `GET /v1/proposals/{chunk_id}` — immediate status.
- `GET /v1/proposals/{chunk_id}/wait?timeout=300` — long-poll until
  approved/rejected (or timeout). On approve, read `policy_reloaded`.

## Workflow

1. Read the deny JSON body (`host`, `port`, `detail`, `next_steps`).
2. `GET /v1/policy/current` and `/v1/denials` if needed.
3. Prefer L7 `protocol: rest` or `protocol: mcp` with exact method/path/tool.
4. `POST /v1/proposals` with one narrow `addRule`.
5. Tell the operator the `chunk_id`. They run:
   `whaleshell rule approve --chunk-id <id>` (or `whaleshell rule reject --chunk-id <id> --reason …`).
6. `GET /v1/proposals/{id}/wait?timeout=300`:
   - `approved` + `policy_reloaded: true` → retry the original request.
   - `approved` + `policy_reloaded: false` → wait once more (`timeout=30`).
   - `rejected` → read `rejection_reason`, revise, resubmit.
   - `timed_out: true` → still pending; wait again.

## Proposal shape

```json
{
  "intent_summary": "Allow agent to call api.github.com Contents API write",
  "operations": [
    {
      "addRule": {
        "ruleName": "github_api_contents_write",
        "rule": {
          "endpoints": [
            {
              "host": "api.github.com",
              "port": 443,
              "protocol": "rest",
              "tls": "terminate",
              "rules": [
                { "allow": { "method": "PUT", "path": "/repos/*/contents/**" } }
              ]
            }
          ]
        }
      }
    }
  ]
}
```

Never propose metadata / link-local targets. Never mount host `~/.cursor` or secrets dirs.
