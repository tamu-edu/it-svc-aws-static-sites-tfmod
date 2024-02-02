locals {
  
  #domain = "${var.deployment}.${var.site_settings.route53_domain}"
  domain = "${var.site_settings.top_level_domain}.${var.deployment}.${var.route53_tld}"
  sans = distinct(concat(
    [local.domain],
    # This is for the top-level domain in production only
    var.site_settings.top_level_domain == "" || var.deployment != "prod" ? [] : [var.site_settings.top_level_domain],
    var.site_settings.additional_domains == null ? tolist([]) : (var.deployment != "prod" ? tolist([]) : tolist(var.site_settings.additional_domains),
    # This is for the optional global accelerator
    var.global_accelerator_source == "" ? [] : [var.global_accelerator_source],
    try(var.site_settings.additional_certs, var.additional_certs)
  ))

}

resource "aws_acm_certificate" "cert" {
  domain_name               = local.domain
  subject_alternative_names = local.sans
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# Cert validation entries for anything with a route53 address
resource "aws_route53_record" "site_val_record" {
  for_each = {
    # for dvo in length(aws_acm_certificate.fqdn) > 0 ? aws_acm_certificate.fqdn[0].domain_validation_options : toset([]) : dvo.domain_name => {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    } if length(regexall(var.route53_tld, dvo.domain_name)) > 0
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.subdomain.zone_id
}

resource "infoblox_cname_record" "aws_cert_cname_record_tamu"{
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    #} if length(regexall("${var.site_settings.top_level_domain}$", dvo.domain_name)) > 0
    } if endswith(dvo.domain_name, "tamu.edu") && !endswith(dvo.domain_name, "cloud.tamu.edu")
  }

  canonical	= trim(each.value.record, ".")
  alias 		= trim(each.value.name, ".")
  ttl 			= 3600
	dns_view	= "TAMU"
  comment 	= "Certificate validation record for AWS static site ${var.site_settings.top_level_domain}"
}

resource "infoblox_cname_record" "aws_cert_cname_record_internet"{
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    #} if length(regexall("${var.site_settings.top_level_domain}$", dvo.domain_name)) > 0
    } if endswith(dvo.domain_name, "tamu.edu") && !endswith(dvo.domain_name, "cloud.tamu.edu")
  }

  canonical	= trim(each.value.record, ".")
  alias 		= trim(each.value.name, ".")
  ttl 			= 3600
	dns_view	= "Internet"
  comment 	= "Certificate validation record for AWS static site ${var.site_settings.top_level_domain}"
}

# Validate certs. This will fail on a non-route53 domain
resource "aws_acm_certificate_validation" "cert" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = []
  depends_on = [
    aws_route53_record.site_val_record,
    infoblox_cname_record.aws_cert_cname_record_tamu,
    infoblox_cname_record.aws_cert_cname_record_internet
  ]

  timeouts {
    create = "10m"
  }
}
