output "aws_iam_access_key_id" {
  value     = aws_iam_access_key.key.id
  sensitive = true
}

output "aws_iam_access_key_secret" {
  value     = aws_iam_access_key.key.secret
  sensitive = true
}

output "cloudfront_aliases" {
  value = aws_cloudfront_distribution.site.aliases
}

output "deployment" {
  value = var.deployment
}

output "top_level_domain" {
  value = var.site_settings.top_level_domain
}
