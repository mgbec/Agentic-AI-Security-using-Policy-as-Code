# Conftest (OPA/Rego) policy for the Terraform plan JSON.
# Evaluated against `terraform show -json tfplan.binary > tfplan.json`.
#
# Run:
#   conftest test terraform/tfplan.json --policy policies/opa --namespace tfplan
#
# Covers the infra preconditions for agentic runtime controls:
#   ASI03 - agent IAM roles must use short-lived sessions
#   ASI08 - agent compute must be bounded (no unlimited concurrency)
#   ASI10 - a kill-switch mechanism (SSM parameter) must exist + logging on

package tfplan

import rego.v1

resources_of(type) := [r |
	some r in input.planned_values.root_module.resources
	r.type == type
]

# ---------------------------------------------------------------------------
# ASI03: Identity & Privilege Abuse - agent roles short-lived (<= 1h).
# ---------------------------------------------------------------------------
deny contains msg if {
	some role in resources_of("aws_iam_role")
	role.values.tags.role == "agent"
	duration := object.get(role.values, "max_session_duration", 3600)
	duration > 3600
	msg := sprintf(
		"ASI03: agent role '%s' max_session_duration %d > 3600s",
		[role.address, duration],
	)
}

# ---------------------------------------------------------------------------
# ASI08: Cascading Failures - bound agent Lambda concurrency.
# ---------------------------------------------------------------------------
deny contains msg if {
	some fn in resources_of("aws_lambda_function")
	fn.values.tags.role == "agent"
	rc := object.get(fn.values, "reserved_concurrent_executions", -1)
	rc == -1
	msg := sprintf(
		"ASI08: agent function '%s' has unbounded concurrency (set reserved_concurrent_executions)",
		[fn.address],
	)
}

# ---------------------------------------------------------------------------
# ASI10: Rogue Agents - a kill-switch SSM parameter must exist, and agent
# functions must emit logs.
# ---------------------------------------------------------------------------
deny contains msg if {
	count(resources_of("aws_lambda_function")) > 0
	count([p |
		some p in resources_of("aws_ssm_parameter")
		contains(p.values.name, "kill-switch")
	]) == 0
	msg := "ASI10: no kill-switch SSM parameter found for agent control"
}

warn contains msg if {
	some fn in resources_of("aws_lambda_function")
	fn.values.tags.role == "agent"
	count([g |
		some g in resources_of("aws_cloudwatch_log_group")
		contains(g.values.name, fn.values.function_name)
	]) == 0
	msg := sprintf(
		"ASI10: agent function '%s' has no explicit CloudWatch log group",
		[fn.address],
	)
}
