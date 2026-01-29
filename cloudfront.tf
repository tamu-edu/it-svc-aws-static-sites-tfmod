locals {
  aliases = distinct(concat(
    [local.domain],
    var.site_settings.top_level_domain == "" || var.deployment != "prod" ? [] : [var.site_settings.top_level_domain],
    var.site_settings.additional_domains == null ? tolist([]) : tolist(var.site_settings.additional_domains),
    try(var.site_settings.additional_cloudfront_aliases, tolist([]))
  ))

  rewrite_rules_location = "https://${var.site_settings.top_level_domain}.${var.deployment}.${var.route53_tld}/rewrite_rules.json"

  #use_response_headers_default_policy = !(
  #  try(var.site_settings.content_security_policy, null) != null ||
  #  try(var.site_settings.x_frame_options, null) != null ||
  #  try(var.site_settings.cors_allowed_headers, null) != null ||
  #  try(var.site_settings.cors_allowed_methods, null) != null ||
  #  try(var.site_settings.cors_allowed_origins, null) != null
  #)
  use_response_headers_default_policy = false
  response_headers_policy_id          = local.use_response_headers_default_policy ? data.aws_cloudfront_response_headers_policy.site_default.id : aws_cloudfront_response_headers_policy.site[0].id

  use_oac_default_policy = false
}

# This data source doesn't work for CLOUDFRONT-scoped web ACLs (only REGIONAL)
/*
data "aws_waf_web_acl" "default_cf_web_acl" {
  name = "default-cf-web-acl"
}
*/

# This is a hack to get the web ACL ARN for the default web ACL given the above mentioned limitation
data "external" "default_cf_web_acl" {
  program = ["bash", "-c", <<EOT
aws wafv2 list-web-acls --scope CLOUDFRONT --query "WebACLs[?Name=='${var.web_acl_name}'] | [0]"
EOT
  ]
}


resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Static Website + Lambda@Edge (${var.deployment})"
  aliases             = local.aliases
  default_root_object = "index.html"
  web_acl_id          = data.external.default_cf_web_acl.result.ARN


  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.cert.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = var.minimum_protocol_version
  }

  origin {
    #domain_name = aws_s3_bucket.bucket.bucket_domain_name
    #origin_id   = aws_s3_bucket.bucket.id
    #custom_origin_config {
    #  http_port              = "80"
    #  https_port             = "443"
    #  origin_protocol_policy = "https-only"
    #  origin_ssl_protocols   = var.origin_ssl_protocols
    #}
    domain_name = aws_s3_bucket.bucket.bucket_regional_domain_name
    origin_id   = aws_s3_bucket.bucket.bucket
    #origin_access_control_id = aws_cloudfront_origin_access_control.site.id
    #origin_access_control_id = data.aws_cloudfront_origin_access_control.site.id
    origin_access_control_id = local.use_oac_default_policy ? data.aws_cloudfront_origin_access_control.site.id : aws_cloudfront_origin_access_control.site[0].id
    custom_header {
      name  = "rules-cache-timeout"
      value = try(var.site_settings.rules_cache_timeout, var.rules_cache_timeout)
    }

    custom_header {
      name = "rules-url"
      #value = try(var.site_settings.rewrite_rules_location, var.rewrite_rules_location)
      value = try(var.site_settings.rewrite_rules_location, local.rewrite_rules_location)
    }
  }

  custom_error_response {
    error_code         = 404
    response_code      = 404
    response_page_path = try(var.site_settings.error_response_404_path, var.error_response_404_path)
  }

  custom_error_response {
    error_code         = 403
    response_code      = 403
    response_page_path = try(var.site_settings.error_response_403_path, var.error_response_403_path)
  }

  default_cache_behavior {
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = true
      # Include query strings, but don't use them for caching
      query_string_cache_keys = []

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }
    compress               = true
    viewer_protocol_policy = "redirect-to-https"

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl     = try(var.site_settings.min_ttl, var.min_ttl)
    default_ttl = try(var.site_settings.default_ttl, var.default_ttl)
    max_ttl     = try(var.site_settings.max_ttl, var.max_ttl)
  }

  ordered_cache_behavior {
    path_pattern               = "index.html"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD", "OPTIONS"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false
      headers      = local.enable_hostname_header_caching ? ["Origin", "X-Forwarded-Host"] : ["Origin"]

      cookies {
        forward = "none"
      }
    }

    # We don't normally do rewrites on index files, but in the case of a hostname-based
    # redirect site, we need to.
    # CHANGED: We now need to do this or we can't do redirects on "/" of a page
    #dynamic "lambda_function_association" {
    #  for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

    #  content {
    #    event_type   = "origin-request"
    #    lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
    #    include_body = false
    #  }
    #}
    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    # We don't normally do rewrites on index files, but in the case of a hostname-based
    # redirect site, we need to
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.index_ttl, var.index_ttl)
    default_ttl            = try(var.site_settings.index_ttl, var.index_ttl)
    max_ttl                = try(var.site_settings.index_ttl, var.index_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "/rewrite_rules.json"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    // Don't run the orgin request lambda because we don't want to rewrite the rules file

    min_ttl                = try(var.site_settings.rules_cache_timeout, var.rules_cache_timeout)
    default_ttl            = try(var.site_settings.rules_cache_timeout, var.rules_cache_timeout)
    max_ttl                = try(var.site_settings.rules_cache_timeout, var.rules_cache_timeout)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "*.html"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.html_ttl, var.html_ttl)
    default_ttl            = try(var.site_settings.html_ttl, var.html_ttl)
    max_ttl                = try(var.site_settings.html_ttl, var.html_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "*.css"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.css_ttl, var.css_ttl)
    default_ttl            = try(var.site_settings.css_ttl, var.css_ttl)
    max_ttl                = try(var.site_settings.css_ttl, var.css_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "*.js"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.javascript_ttl, var.javascript_ttl)
    default_ttl            = try(var.site_settings.javascript_ttl, var.javascript_ttl)
    max_ttl                = try(var.site_settings.javascript_ttl, var.javascript_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "*.jpg"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.media_ttl, var.media_ttl)
    default_ttl            = try(var.site_settings.media_ttl, var.media_ttl)
    max_ttl                = try(var.site_settings.media_ttl, var.media_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "*.png"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.media_ttl, var.media_ttl)
    default_ttl            = try(var.site_settings.media_ttl, var.media_ttl)
    max_ttl                = try(var.site_settings.media_ttl, var.media_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "*.gif"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.media_ttl, var.media_ttl)
    default_ttl            = try(var.site_settings.media_ttl, var.media_ttl)
    max_ttl                = try(var.site_settings.media_ttl, var.media_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "*.svg"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.media_ttl, var.media_ttl)
    default_ttl            = try(var.site_settings.media_ttl, var.media_ttl)
    max_ttl                = try(var.site_settings.media_ttl, var.media_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern               = "*.pdf"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = aws_s3_bucket.bucket.id
    response_headers_policy_id = local.response_headers_policy_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }

      headers = local.enable_hostname_header_caching ? ["X-Forwarded-Host"] : null
    }

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_rewrite.qualified_arn
      include_body = false
    }

    #lambda_function_association {
    #  event_type   = "origin-response"
    #  lambda_arn   = aws_lambda_function.edge_security.qualified_arn
    #  include_body = false
    #}

    # Not compatible with host headers (i.e. an external redirect site config)
    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([]) : (local.sso_required ? toset([0]) : toset([]))

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.oidc_auth[0].qualified_arn
        include_body = false
      }
    }

    dynamic "lambda_function_association" {
      for_each = local.enable_hostname_rewrites ? toset([0]) : toset([])

      content {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.edge_host_header[0].qualified_arn
        include_body = false
      }
    }

    min_ttl                = try(var.site_settings.pdf_ttl, var.pdf_ttl)
    default_ttl            = try(var.site_settings.pdf_ttl, var.pdf_ttl)
    max_ttl                = try(var.site_settings.pdf_ttl, var.pdf_ttl)
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.bucket_logging.bucket_domain_name
    prefix          = var.deployment
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  depends_on = [
    aws_acm_certificate_validation.cert,
    aws_s3_bucket_ownership_controls.bucket,
    aws_s3_bucket_ownership_controls.bucket_logging
  ]
}


resource "aws_cloudfront_response_headers_policy" "site" {
  count   = local.use_response_headers_default_policy ? 0 : 1
  name    = "site-headers-policy-${replace(var.site_settings.top_level_domain, ".", "_")}-${var.deployment}"
  comment = "Site Headers Policy (${var.site_settings.top_level_domain}-${var.deployment})"

  security_headers_config {
    content_type_options {
      override = true
    }

    referrer_policy {
      referrer_policy = "same-origin"
      override        = true
    }

    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }

    strict_transport_security {
      access_control_max_age_sec = "63072000"
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    content_security_policy {
      content_security_policy = try(var.site_settings.content_security_policy, var.content_security_policy)
      override                = true
    }

    frame_options {
      frame_option = try(var.site_settings.x_frame_options, var.x_frame_options)
      override     = true
    }
  }

  cors_config {
    access_control_allow_credentials = true

    access_control_allow_headers {
      items = try(var.site_settings.cors_allowed_headers, var.cors_allowed_headers)
    }

    access_control_allow_methods {
      items = try(var.site_settings.cors_allowed_methods, var.cors_allowed_methods)
    }

    access_control_allow_origins {
      items = try(var.site_settings.cors_allowed_origins, var.cors_allowed_origins)
    }

    origin_override = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_cloudfront_response_headers_policy" "site_default" {
  name = "site-headers-policy-default"
}


resource "aws_cloudfront_origin_access_control" "site" {
  count                             = local.use_oac_default_policy ? 0 : 1
  name                              = substr("site-origin-access-control-${replace(var.site_settings.top_level_domain, ".", "-")}-${var.deployment}", 0, 64)
  description                       = "Site Policy (${var.site_settings.top_level_domain}-${var.deployment}))"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"

  lifecycle {
    create_before_destroy = true
  }
}

data "external" "get_oac" {
  program = ["bash", "-c", <<EOT
aws cloudfront list-origin-access-controls --query "OriginAccessControlList.Items[?Name=='site-origin-access-control-all-sites'] | [0]"
EOT
  ]
}

data "aws_cloudfront_origin_access_control" "site" {
  id = data.external.get_oac.result.Id
}

output "use_response_headers_default_policy" {
  value = local.use_response_headers_default_policy
}
