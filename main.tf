data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

#  _____                    _                                                   _____                    _   
# /  ___|                  | |                                                 /  ___|                  | |  
# \ `--.  ___  ___ _ __ ___| |_ ___ _ __ ___   __ _ _ __   __ _  __ _  ___ _ __\ `--.  ___  ___ _ __ ___| |_ 
#  `--. \/ _ \/ __| '__/ _ \ __/ __| '_ ` _ \ / _` | '_ \ / _` |/ _` |/ _ \ '__|`--. \/ _ \/ __| '__/ _ \ __|
# /\__/ /  __/ (__| | |  __/ |_\__ \ | | | | | (_| | | | | (_| | (_| |  __/ |  /\__/ /  __/ (__| | |  __/ |_ 
# \____/ \___|\___|_|  \___|\__|___/_| |_| |_|\__,_|_| |_|\__,_|\__, |\___|_|  \____/ \___|\___|_|  \___|\__|
#                                                                __/ |                                       
#                                                               |___/                                        

resource "aws_secretsmanager_secret" "secret" {
  for_each = { for name in var.create_secretsmanager_secrets : name => name }
  name = each.value
}

#  _____  ___  ___  ___ ______ _____ _      _____ 
# |_   _|/ _ \ |  \/  | | ___ \  _  | |    |  ___|
#   | | / /_\ \| .  . | | |_/ / | | | |    | |__  
#   | | |  _  || |\/| | |    /| | | | |    |  __| 
#  _| |_| | | || |  | | | |\ \\ \_/ / |____| |___ 
#  \___/\_| |_/\_|  |_/ \_| \_|\___/\_____/\____/ 
#                   ______                        
#                  |______|                       

data "aws_iam_policy_document" "irsa_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::${local.account_id}:oidc-provider/${var.eks_oidc_issure}"
      ]
    }
    actions   = ["sts:AssumeRoleWithWebIdentity"]
    condition {
      test = "StringEquals"
      variable = "${var.eks_oidc_issure}:aud"
      values = ["sts.amazonaws.com"]
    }
    condition {
      test = "StringEquals"
      variable = "${var.eks_oidc_issure}:sub"
      values = ["system:serviceaccount:external-secrets:${var.external_secrets.service_account_name}"]
    }
  }
}

data "aws_iam_policy_document" "irsa_inline_policy" {
  statement {
    effect = "Allow"
    resources = [
      "arn:aws:kms:*:${local.account_id}:key/*",
      "arn:aws:secretsmanager:*:${local.account_id}:secret:*"
    ]
    actions = [
      "kms:GetPublicKey", "kms:Decrypt", "kms:ListKeyPolicies", "secretsmanager:DescribeSecret", "kms:GetKeyPolicy", "kms:ListResourceTags", 
      "kms:ListGrants", "secretsmanager:ListSecretVersionIds", "kms:GetParametersForImport", "secretsmanager:GetResourcePolicy", 
      "secretsmanager:GetSecretValue", "kms:Encrypt", "kms:GetKeyRotationStatus", "kms:GenerateDataKey", "kms:DescribeKey"
    ]
  }
  statement {
    effect = "Allow"
    resources = ["*"]
    actions = [
      "kms:DescribeCustomKeyStores", "kms:ListKeys", "secretsmanager:GetRandomPassword", "kms:ListRetirableGrants", "kms:ListAliases", 
      "secretsmanager:BatchGetSecretValue", "secretsmanager:ListSecrets"
    ]
  }
}

resource "aws_iam_role" "irsa" { // pms_eks_secretsmanager_irsa
  name = "${var.role_name_prefix}-external-secrets-role"
  inline_policy {
    name = "${var.role_name_prefix}-external-secrets-policy"
    policy = data.aws_iam_policy_document.irsa_inline_policy.json
  }
  assume_role_policy = data.aws_iam_policy_document.irsa_assume_role.json
}

#  _____     _                        _ _____                    _      ___          _         __  
# |  ___|   | |                      | /  ___|                  | |    / / |        | |        \ \ 
# | |____  _| |_ ___ _ __ _ __   __ _| \ `--.  ___  ___ _ __ ___| |_  | || |__   ___| |_ __ ___ | |
# |  __\ \/ / __/ _ \ '__| '_ \ / _` | |`--. \/ _ \/ __| '__/ _ \ __| | || '_ \ / _ \ | '_ ` _ \| |
# | |___>  <| ||  __/ |  | | | | (_| | /\__/ /  __/ (__| | |  __/ |_  | || | | |  __/ | | | | | | |
# \____/_/\_\\__\___|_|  |_| |_|\__,_|_\____/ \___|\___|_|  \___|\__| | ||_| |_|\___|_|_| |_| |_| |
#                                                                      \_\                     /_/ 

resource "helm_release" "external_secret" {
  depends_on = [
    aws_iam_role.irsa
  ]

  namespace = var.external_secrets.namespace
  create_namespace = true

  name = "external-secrets"
  chart = "external-secrets"
  version = var.external_secrets.version
  repository = "https://external-secrets.io"
  values = [
    <<-EOT
    serviceAccount:
      annotations:
        eks.amazonaws.com/role-arn: ${aws_iam_role.irsa.arn}
      name: ${var.external_secrets.service_account_name}
    EOT
  ]
}
