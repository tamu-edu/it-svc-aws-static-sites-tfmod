locals {
  oid_secret_name   = "${var.oidc_auth_config_secret_name_base}/${var.site_settings.top_level_domain}"
  callback_fqdn = var.deployment == "prod" ? var.site_settings.top_level_domain : local.domain

  sso_required = try(var.site_settings.sso_required, var.sso_required)
  sso_pages = try(var.site_settings.sso_pages, var.sso_pages)
  sso_secret_name = "${var.sso_pages_secret_name_base}/${var.site_settings.top_level_domain}"
}


resource "aws_secretsmanager_secret" "cf_oidc_config" {
  count = local.sso_required ? 1 : 0

  name        = local.oid_secret_name
  description = "Credentials for setting up site authentication via OIDC"
}

resource "aws_secretsmanager_secret_version" "cf_oidc_config" {
  count     = local.sso_required ? 1 : 0

  secret_id = aws_secretsmanager_secret.cf_oidc_config[0].id
  secret_string = jsonencode({
    "config" = base64encode(jsonencode({
      AUTH_REQUEST = {
        client_id     = var.oidc_client_id
        response_type = "code"
        scope         = "openid email"
        #redirect_uri  = "https://${aws_cloudfront_distribution.site.domain_name}/_callback"
        redirect_uri = "https://${local.callback_fqdn}/_callback"
      }
      TOKEN_REQUEST = {
        client_id = var.oidc_client_id
        #redirect_uri  = "https://${aws_cloudfront_distribution.site.domain_name}/_callback"
        redirect_uri  = "https://${local.callback_fqdn}/_callback"
        grant_type    = "authorization_code"
        client_secret = var.oidc_client_secret
      }
      DISTRIBUTION = "amazon-oai"
      AUTHN        = "ENTRAID"
      # Make sure that we don't have any twice-escaped newlines
      PRIVATE_KEY        = replace(var.oidc_private_key, "\\n", "\n")
      PUBLIC_KEY         = replace(var.oidc_public_key, "\\n", "\n")
      DISCOVERY_DOCUMENT = "https://login.microsoftonline.com/tamucs.onmicrosoft.com/v2.0/.well-known/openid-configuration"
      SESSION_DURATION   = try(var.site_settings.oidc_session_duration, var.oidc_session_duration)
      BASE_URL           = "https://login.microsoftonline.com/"
      CALLBACK_PATH      = "/_callback"
      AUTHZ              = "ENTRAID"
    }))
  })
}

resource "aws_secretsmanager_secret" "sso_pages" {
  count = local.sso_required ? 1 : 0

  name        = local.sso_secret_name
  description = "A list of regular expressions that will be used to determine which pages require SSO authentication"
}

resource "aws_secretsmanager_secret_version" "sso_pages" {
  count     = local.sso_required ? 1 : 0

  secret_id = aws_secretsmanager_secret.sso_pages[0].id
  secret_string = join(";", local.sso_pages)
}