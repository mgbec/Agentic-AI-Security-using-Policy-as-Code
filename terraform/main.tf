terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  # 'role = agent' marks resources the ASI policies apply to; owner/environment
  # satisfy inventory (ASI10).
  agent_tags = {
    role        = "agent"
    owner       = var.owner
    environment = var.environment
    project     = "owasp-agentic-policy-as-code"
  }
}

# ---------------------------------------------------------------------------
# ASI03 Identity & Privilege Abuse
# Scoped, short-lived agent role. max_session_duration pinned to 1h.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "agent" {
  name = "${var.agent_name}-agent-role"

  # 1 hour (3600s) -> satisfies CKV_ASI03_1 and the OPA tfplan rule.
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = local.agent_tags
}

# Least-privilege inline policy: read-only GitHub token from Secrets Manager,
# write only to its own log group. No wildcards on resources.
resource "aws_iam_role_policy" "agent" {
  name = "${var.agent_name}-agent-policy"
  role = aws_iam_role.agent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAgentSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.agent_token.arn]
      },
      {
        Sid      = "WriteOwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.agent.arn}:*"]
      },
      {
        Sid      = "ReadKillSwitch"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = [aws_ssm_parameter.kill_switch.arn]
      }
    ]
  })
}

# ASI03: short-lived, rotated credential rather than a long-lived token.
resource "aws_secretsmanager_secret" "agent_token" {
  name                    = "${var.agent_name}/github-readonly-token"
  recovery_window_in_days = 7
  tags                    = local.agent_tags
}

# ---------------------------------------------------------------------------
# ASI10 Rogue Agents - kill switch the runtime checks before each run.
# The agent reads this flag; flip to "disabled" to revoke the agent fast.
# ---------------------------------------------------------------------------
resource "aws_ssm_parameter" "kill_switch" {
  name        = "/agents/${var.agent_name}/kill-switch"
  description = "Set to 'disabled' to immediately halt the agent (ASI10)."
  type        = "String"
  value       = "enabled"
  tags        = local.agent_tags
}

# ---------------------------------------------------------------------------
# ASI10 observability + ASI08 blast-radius control
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "agent" {
  name              = "/aws/lambda/${var.agent_name}-agent"
  retention_in_days = 365
  tags              = local.agent_tags
}

resource "aws_lambda_function" "agent" {
  function_name = "${var.agent_name}-agent"
  role          = aws_iam_role.agent.arn
  runtime       = "python3.12"
  handler       = "agent_handler.run_agent"
  filename      = "${path.module}/lambda/agent.zip"

  # ASI08 Cascading Failures: bound concurrency so a runaway agent cannot
  # fan out across the account.
  reserved_concurrent_executions = 5
  timeout                        = 30
  memory_size                    = 512

  environment {
    variables = {
      KILL_SWITCH_PARAM = aws_ssm_parameter.kill_switch.name
      MAX_TOOL_CALLS    = "10"
    }
  }

  tags = local.agent_tags
}
