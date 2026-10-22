# Conftest (OPA/Rego) policy for the agentic supply chain.
# Evaluated against agents/tools/tools.yaml and agents/mcp/mcp.json.
#
# Run:
#   conftest test agents/tools/tools.yaml --policy policies/opa --namespace supplychain
#   conftest test agents/mcp/mcp.json --policy policies/opa --namespace supplychain
#
# Covers ASI04 - Agentic Supply Chain Vulnerabilities:
#   tools and MCP servers must be pinned, integrity-checked, and allowlisted,
#   so components cannot be swapped or tampered with at runtime.

package supplychain

import rego.v1

semver := `^\d+\.\d+\.\d+$`

# ---------------------------------------------------------------------------
# Tool manifest (ASI04)
# ---------------------------------------------------------------------------
deny contains msg if {
	some tool in input.tools
	not tool.source.version
	msg := sprintf("ASI04: tool '%s' has no pinned source.version", [tool.name])
}

deny contains msg if {
	some tool in input.tools
	version := tool.source.version
	not regex.match(semver, version)
	msg := sprintf(
		"ASI04: tool '%s' version '%s' is not an exact pin (no ranges/latest)",
		[tool.name, version],
	)
}

deny contains msg if {
	some tool in input.tools
	not tool.source.integrity
	msg := sprintf("ASI04: tool '%s' has no source.integrity hash", [tool.name])
}

# ASI02: mutating tools must require approval.
deny contains msg if {
	some tool in input.tools
	tool.mutating == true
	not tool.requiresApproval == true
	msg := sprintf(
		"ASI02: mutating tool '%s' must set requiresApproval = true",
		[tool.name],
	)
}

# ---------------------------------------------------------------------------
# MCP servers (ASI04 + ASI07)
# ---------------------------------------------------------------------------
deny contains msg if {
	some name, server in input.mcpServers
	not server.allowlisted == true
	msg := sprintf("ASI04: MCP server '%s' is not allowlisted", [name])
}

deny contains msg if {
	some name, server in input.mcpServers
	not regex.match(semver, server.pinnedVersion)
	msg := sprintf(
		"ASI04: MCP server '%s' pinnedVersion '%s' is not an exact pin",
		[name, server.pinnedVersion],
	)
}

deny contains msg if {
	some name, server in input.mcpServers
	not server.integrity
	msg := sprintf("ASI04: MCP server '%s' has no integrity hash", [name])
}

# ASI07: networked MCP transports must not be unauthenticated.
deny contains msg if {
	some name, server in input.mcpServers
	server.transport in {"http", "sse"}
	not server.env
	msg := sprintf(
		"ASI07: networked MCP server '%s' (%s) has no auth/env configured",
		[name, server.transport],
	)
}
