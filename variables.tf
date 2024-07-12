variable "role_name_prefix" {
    type = string
}

variable "create_secretsmanager_secrets" {
    type = list(string)
}

variable "eks_oidc_issure" {
    type = string
}

variable "service_account_name" {
    type = string
    default = "external-secrets"
}

variable "external_secrets" {
    type = object({
      version = optional(string, "0.9.20")
      namespace = optional(string, "external-secrets")
      service_account_name = optional(string, "external-secrets")
    })
    default = {
      version = "0.9.20",
      namespace = "external-secrets"
      service_account_name = "external-secrets"
    }
}
