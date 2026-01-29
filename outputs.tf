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

output "external_validation_records" {
  value = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
      #} if length(regexall("${var.site_settings.top_level_domain}$", dvo.domain_name)) > 0
    } if endswith(dvo.domain_name, ".cloud.tamu.edu") || contains(var.external_validation_list, dvo.domain_name)
  }
}
