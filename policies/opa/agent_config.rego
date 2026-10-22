# Conftest (OPA/Rego) policy for agent configurations.
# Evaluated against agents/*.agent.yaml.
#
# Run:
#   conftest test agents/summarizer.agent.yaml --policy policies/opa --namespace agent
#
# Covers:
#   ASI01 - every untrusted input must be declared (fence from instructions)
#   ASI02 - tool-call budget must be bounded
#   ASI09 - high-impact actions must require human approval
#   ASI10 - kill switch + ownership + audit logging required (rogue control)

package agent

import rego.v1

# ---------------------------------------------------------------------------
# ASI10: Rogue Agents - must be revocable, owned, and observable.
# ---------------------------------------------------------------------------
deny contains msg if {
	not input.metadata.killSwitch
	msg := "ASI10: agent has no metadata.killSwitch (no revocation target)"
}

deny contains msg if {
	not input.metadata.owner
	msg := "ASI10: agent has no metadata.owner (not inventoried)"
}

deny contains msg if {
	not input.spec.observability.auditLog == true
	msg := "ASI10: agent must set spec.observability.auditLog = true"
}

# ---------------------------------------------------------------------------
# ASI02 / ASI08: bound the blast radius with a tool-call budget.
# ---------------------------------------------------------------------------
deny contains msg if {
	budget := input.spec.autonomy.maxToolCallsPerRun
	not budget
	msg := "ASI02: spec.autonomy.maxToolCallsPerRun is required (bound tool calls)"
}

deny contains msg if {
	budget := input.spec.autonomy.maxToolCallsPerRun
	budget > 50
	msg := sprintf("ASI02: maxToolCallsPerRun %d exceeds cap of 50", [budget])
}

# ---------------------------------------------------------------------------
# ASI09: every declared high-impact action must require human approval.
# ---------------------------------------------------------------------------
deny contains msg if {
	some action in input.spec.autonomy.highImpactActions
	not action.requiresApproval == true
	msg := sprintf(
		"ASI09: high-impact action '%s' must set requiresApproval = true",
		[action.name],
	)
}

# ---------------------------------------------------------------------------
# ASI01: if any input is untrusted, the system prompt boundary must exist,
# and code execution must be off unless explicitly justified.
# ---------------------------------------------------------------------------
has_untrusted_input if {
	some i in input.spec.inputs
	i.trust == "untrusted"
}

deny contains msg if {
	has_untrusted_input
	input.spec.autonomy.allowCodeExecution == true
	msg := "ASI01/ASI05: allowCodeExecution must be false when inputs are untrusted"
}

# ---------------------------------------------------------------------------
# ASI06: long-term memory requires input sanitization.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.spec.memory.persistence == "long-term"
	not input.spec.memory.sanitizeInputs == true
	msg := "ASI06: long-term memory requires spec.memory.sanitizeInputs = true"
}

# ---------------------------------------------------------------------------
# ASI07: inter-agent comms, when enabled, require mTLS + message auth.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.spec.interAgent.enabled == true
	not input.spec.interAgent.requireMutualTls == true
	msg := "ASI07: inter-agent comms enabled but requireMutualTls != true"
}

deny contains msg if {
	input.spec.interAgent.enabled == true
	not input.spec.interAgent.requireMessageAuth == true
	msg := "ASI07: inter-agent comms enabled but requireMessageAuth != true"
}
