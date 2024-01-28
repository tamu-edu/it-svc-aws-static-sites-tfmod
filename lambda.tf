locals {
  enable_hostname_rewrites = try(var.site_settings.enable_hostname_rewrites == "true", var.enable_hostname_rewrites)
}

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam-for-lambda-edge-${var.site_settings.top_level_domain}-${var.deployment}"

  assume_role_policy = jsonencode(
    {
      Version = "2012-10-17"
      Statement = [
        {
          Action = "sts:AssumeRole"
          Principal = {
            Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
          },
          Effect = "Allow"
          Sid    = "AssumeRole"
        }
      ]
  })
}

resource "aws_iam_policy" "iam_policy_for_lambda" {

  name        = "aws_iam_policy_for_terraform_aws_lambda_role_${replace(var.site_settings.top_level_domain, ".", "_")}_${var.deployment}"
  path        = "/cloudfront/lambda/"
  description = "AWS IAM Policy for managing aws lambda role"
  policy = jsonencode(
    {
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ]
          Resource = "arn:aws:logs:*:*:*"
          Effect   = "Allow"
        },
        {
          Action = [
            "s3:GetObject",
            "s3:ListBucket",
          ]
          Resource = [
            "arn:aws:s3:::${aws_s3_bucket.bucket.bucket}/*",
            "arn:aws:s3:::${aws_s3_bucket.bucket.bucket}"
          ]
          Effect = "Allow"
        },
        {
          Action = local.sso_required ? [
            "secretsmanager:GetResourcePolicy",
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret",
            "secretsmanager:ListSecretVersionIds"
          ] : ["none:none"]
          Resource = local.sso_required ? [
            aws_secretsmanager_secret.cf_oidc_config[0].arn,
            aws_secretsmanager_secret.sso_pages[0].arn
          ] : ["*"]
          Effect = "Allow"
        }
      ]
  })
}

#resource "aws_cloudwatch_log_group" "rewrite_log_group" {
#  name              = "/aws/lambda/${aws_lambda_function.edge_rewrite.function_name}"
#  retention_in_days = var.log_expiration
#}

#resource "aws_cloudwatch_log_group" "security_log_group" {
#  name              = "/aws/lambda/${aws_lambda_function.edge_security.function_name}"
#  retention_in_days = var.log_expiration
#}

#resource "aws_cloudwatch_log_group" "host_header_log_group" {
#  count = local.enable_hostname_rewrites ? 1 : 0
#
#  name              = "/aws/lambda/${aws_lambda_function.edge_host_header[0].function_name}"
#  retention_in_days = var.log_expiration
#}

resource "aws_iam_role_policy_attachment" "attach_iam_policy_to_iam_role" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.iam_policy_for_lambda.arn
}


resource "aws_lambda_function" "edge_rewrite" {
  filename      = data.archive_file.zip_edge_rewrite.output_path
  function_name = "LambdaEdgeRewriteFunction-${replace(var.site_settings.top_level_domain, ".", "_")}-${var.deployment}"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"
  publish       = true
  timeout       = 10

  source_code_hash = data.archive_file.zip_edge_rewrite.output_base64sha256

  runtime = "nodejs${var.lambda_runtime}.x"

}

#resource "aws_lambda_function" "edge_security" {
#  filename      = data.archive_file.zip_edge_security.output_path
#  function_name = "LambdaEdgeSecurityFunction-${var.deployment}"
#  role          = aws_iam_role.iam_for_lambda.arn
#  handler       = "index.handler"
#  publish       = true
#
#  source_code_hash = data.archive_file.zip_edge_security.output_base64sha256
#
#  runtime = "nodejs${var.lambda_runtime}.x"
#
#}

resource "aws_lambda_function" "oidc_auth" {
  count = local.enable_hostname_rewrites ? 0 : (local.sso_required ? 1 : 0)
  filename      = data.archive_file.oidc_auth[0].output_path
  function_name = "OIDCAuthFunction-${replace(var.site_settings.top_level_domain, ".", "_")}-${var.deployment}"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "auth.handle"
  publish       = true

  source_code_hash = data.archive_file.oidc_auth[0].output_base64sha256

  runtime = "nodejs${var.lambda_runtime}.x"

}

resource "aws_lambda_function" "edge_host_header" {
  count = local.enable_hostname_rewrites ? 1 : 0

  filename      = data.archive_file.zip_edge_host_header[0].output_path
  function_name = "LambdaEdgeHostHeaderFunction-${replace(var.site_settings.top_level_domain, ".", "_")}-${var.deployment}"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"
  publish       = true

  source_code_hash = data.archive_file.zip_edge_host_header[0].output_base64sha256

  runtime = "nodejs${var.lambda_runtime}.x"

}

# Vendor the dependencies
data "external" "rewrite_lambda_dependencies" {
  program = ["bash", "-c", <<EOT
(cd ${path.module}/LambdaEdgeFunctions/rewrite && LAMBDA_FUNCTION_NAME=rewrite \
  LAMBDA_RUNTIME=${var.lambda_runtime} docker compose up; docker compose down) >&2 > /tmp/rewrite.log && \
echo "{\"target_dir\": \"${path.module}/LambdaEdgeFunctions/rewrite\"}"
EOT
  ]
}

# Vendor the dependencies
#data "external" "security_lambda_dependencies" {
#  program = ["bash", "-c", <<EOT
#(cd ${path.module}/LambdaEdgeFunctions/security && LAMBDA_FUNCTION_NAME=security \
#  LAMBDA_RUNTIME=${var.lambda_runtime} docker compose up; docker compose down) >&2 > /tmp/security.log && \
#echo "{\"target_dir\": \"${path.module}/LambdaEdgeFunctions/security\"}"
#EOT
#  ]
#}

# Vendor the dependencies
data "external" "oidc_auth_lambda_dependencies" {
  count = local.enable_hostname_rewrites ? 0 : (local.sso_required ? 1 : 0)

  program = ["bash", "-c", <<EOT
(cd ${path.module}/LambdaEdgeFunctions/oidc_auth && LAMBDA_FUNCTION_NAME=oidc_auth \
  LAMBDA_RUNTIME=${var.lambda_runtime} docker compose up; docker compose down) >&2 > /tmp/oidc_auth.log && \
echo "{\"target_dir\": \"${path.module}/LambdaEdgeFunctions/oidc_auth\"}"
EOT
  ]

  depends_on = [ 
    local_file.sm_key,
    local_file.sm_key_sso_pages
  ]
}

resource "local_file" "sm_key" {
  count = local.sso_required ? 1 : 0

  filename = "${path.module}/LambdaEdgeFunctions/oidc_auth/sm-key.txt"
  content  = local.oid_secret_name
}

resource "local_file" "sm_key_sso_pages" {
  count = local.sso_required ? 1 : 0

  filename = "${path.module}/LambdaEdgeFunctions/oidc_auth/sm-key-sso-pages.txt"
  content  = local.sso_secret_name
}

data "external" "host_header_lambda_dependencies" {
  count = local.enable_hostname_rewrites ? 1 : 0

  program = ["bash", "-c", <<EOT
(cd ${path.module}/LambdaEdgeFunctions/host_header && LAMBDA_FUNCTION_NAME=host_header \
  LAMBDA_RUNTIME=${var.lambda_runtime} docker compose up; docker compose down) >&2 > /tmp/host_header.log && \
echo "{\"target_dir\": \"${path.module}/LambdaEdgeFunctions/host_header\"}"
EOT
  ]
}

# The output_file_mode makes this zip file deterministic across environments
data "archive_file" "zip_edge_rewrite" {
  type             = "zip"
  source_dir       = data.external.rewrite_lambda_dependencies.result.target_dir
  output_path      = "${path.module}/LambdaEdgeRewriteFunction-${var.site_settings.top_level_domain}-${var.deployment}.zip"
  output_file_mode = "0666"
}

# The output_file_mode makes this zip file deterministic across environments
#data "archive_file" "zip_edge_security" {
#  type             = "zip"
#  source_dir       = data.external.security_lambda_dependencies.result.target_dir
#  output_path      = "${path.module}/LambdaEdgeSecurityFunction.zip"
#  output_file_mode = "0666"
#}

# The output_file_mode makes this zip file deterministic across environments
data "archive_file" "oidc_auth" {
  count = local.enable_hostname_rewrites ? 0 : (local.sso_required ? 1 : 0)

  type             = "zip"
  source_dir       = data.external.oidc_auth_lambda_dependencies[0].result.target_dir
  output_path      = "${path.module}/LambdaEdgeOIDCAuthFunction-${var.site_settings.top_level_domain}-${var.deployment}.zip"
  output_file_mode = "0666"
}

data "archive_file" "zip_edge_host_header" {
  count = local.enable_hostname_rewrites ? 1 : 0

  type             = "zip"
  source_dir       = data.external.host_header_lambda_dependencies[0].result.target_dir
  output_path      = "${path.module}/LambdaEdgeHostHeaderFunction-${var.site_settings.top_level_domain}-${var.deployment}.zip"
  output_file_mode = "0666"
}



# This was moved to lambda.tf so that localstack could use that file independently
variable "enable_hostname_rewrites" {
  type        = bool
  description = "Whether or not to install a viewer lambda to capture the original hostname as an additional header to enable rewrites based on hostname, not just URI"
  default     = false
}
variable "lambda_runtime" {
  type        = number
  description = "The node.js runtime version to use for the lambda@edge function"
  default     = 20
}
variable "site_settings" {
  #type        = map(any)
  description = "A map of site settings that represent user-configurable parameters"
  default     = {}
}
