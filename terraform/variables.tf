variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "dev"
}

variable "owner" {
  description = "Owning team (inventory ownership for ASI10)."
  type        = string
  default     = "platform-security"
}

variable "agent_name" {
  description = "Name of the agent workload."
  type        = string
  default     = "pr-summarizer"
}
