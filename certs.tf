locals {

  #domain = "${var.deployment}.${var.site_settings.route53_domain}"
  domain = "${var.site_settings.top_level_domain}.${var.deployment}.${var.route53_tld}"
  sans = distinct(concat(
    [local.domain],
    # This is for the top-level domain in production only
    var.site_settings.top_level_domain == "" || var.deployment != "prod" ? [] : [var.site_settings.top_level_domain],
    var.site_settings.additional_domains == null ? tolist([]) : (var.deployment != "prod" ? tolist([]) : tolist(var.site_settings.additional_domains)),
    var.site_settings.external_domains == null ? tolist([]) : tolist(var.site_settings.external_domains),
    # This is for the optional global accelerator
    try(var.site_settings.global_accelerator, "") == "" ? [] : flatten([var.site_settings.global_accelerator]),
    try(var.site_settings.additional_certs, var.additional_certs)
  ))

  use_infoblox = try(tobool(var.site_settings.use_infoblox), true)

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

resource "infoblox_cname_record" "aws_cert_cname_record_tamu" {
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
      #} if length(regexall("${var.site_settings.top_level_domain}$", dvo.domain_name)) > 0
    } if endswith(dvo.domain_name, "tamu.edu") && !endswith(dvo.domain_name, ".cloud.tamu.edu") && !contains(var.site_settings.external_domains, dvo.domain_name) && local.use_infoblox
  }

  canonical = trim(each.value.record, ".")
  alias     = trim(each.value.name, ".")
  ttl       = 3600
  dns_view  = "TAMU"
  comment   = "Certificate validation record for AWS static site ${var.site_settings.top_level_domain}"
}

resource "infoblox_cname_record" "aws_cert_cname_record_internet" {
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
      #} if length(regexall("${var.site_settings.top_level_domain}$", dvo.domain_name)) > 0
    } if endswith(dvo.domain_name, "tamu.edu") && !endswith(dvo.domain_name, ".cloud.tamu.edu") && !contains(var.site_settings.external_domains, dvo.domain_name) && local.use_infoblox
  }

  canonical = trim(each.value.record, ".")
  alias     = trim(each.value.name, ".")
  ttl       = 3600
  dns_view  = "Internet"
  comment   = "Certificate validation record for AWS static site ${var.site_settings.top_level_domain}"
}


# Print external DNS records to screen for manual operator creation

locals {
  manual_dvos = { for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
    name   = dvo.resource_record_name
    record = dvo.resource_record_value
    type   = dvo.resource_record_type
    } if contains(var.site_settings.external_domains, dvo.domain_name)
  }
  records_output = join("\n", [for domain, dvo in local.manual_dvos : <<-EOT
    Create the following DNS Record (for ${domain}):
    Type:  ${dvo.type}
    Name:  ${dvo.name}
    Value: ${dvo.record}
    ------------------------------------------------------------------------
    EOT
  ])
}

resource "terraform_data" "external_dns_instructions" {
  # This triggers the resource to run every time the cert changes
  input            = aws_acm_certificate.cert.arn
  triggers_replace = aws_acm_certificate.cert.arn

  # Echo the values to stdout using local-exec
  provisioner "local-exec" {
    command = <<EOT
      cat <<'EOF'


------------------------------------------------------------------------
MANUAL DNS RECORDS REQUIRED FOR CERTIFICATE VALIDATION
Certificate validation will not succeed until these records are created.
------------------------------------------------------------------------
${local.records_output}

EOF
    EOT
  }
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
