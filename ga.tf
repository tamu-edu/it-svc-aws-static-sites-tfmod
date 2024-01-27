# Set up a global accelerator if requested

locals {
  ga = var.global_accelerator_source == "" ? false : true
}

resource "aws_globalaccelerator_accelerator" "site_ga" {
  count           = local.ga ? 1 : 0
  name            = substr(replace("${var.global_accelerator_source}-${var.global_accelerator_target}", ".", "-"), 0, 64)
  ip_address_type = "IPV4"
  enabled         = true

  attributes {
    flow_logs_enabled   = true
    flow_logs_s3_bucket = aws_s3_bucket.bucket_logging.bucket
    flow_logs_s3_prefix = "ga-flow-logs/"
  }
}

resource "aws_globalaccelerator_listener" "ga_listener_80" {
  count = local.ga ? 1 : 0

  accelerator_arn = aws_globalaccelerator_accelerator.site_ga[0].id
  client_affinity = "SOURCE_IP"
  protocol        = "TCP"

  port_range {
    from_port = 80
    to_port   = 80
  }
}

resource "aws_globalaccelerator_listener" "ga_listener_443" {
  count = local.ga ? 1 : 0

  accelerator_arn = aws_globalaccelerator_accelerator.site_ga[0].id
  client_affinity = "SOURCE_IP"
  protocol        = "TCP"

  port_range {
    from_port = 443
    to_port   = 443
  }
}

resource "aws_globalaccelerator_endpoint_group" "ga_endpoint_group_80" {
  count = local.ga ? 1 : 0

  listener_arn = aws_globalaccelerator_listener.ga_listener_80[0].id

  endpoint_configuration {
    endpoint_id = aws_lb.ga_lb[0].arn
    weight      = 100
  }
}

resource "aws_globalaccelerator_endpoint_group" "ga_endpoint_group_443" {
  count = local.ga ? 1 : 0

  listener_arn = aws_globalaccelerator_listener.ga_listener_443[0].id

  endpoint_configuration {
    endpoint_id = aws_lb.ga_lb[0].arn
    weight      = 100
  }
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "5.5.1"

  count = local.ga ? 1 : 0

  name = "ga-lb-site-${var.deployment}-vpc"
  cidr = "10.0.0.0/16"

  azs            = ["us-east-1a", "us-east-1b", "us-east-1c"]
  public_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

  enable_nat_gateway = false
  enable_vpn_gateway = false
}

resource "aws_security_group" "allow_http" {
  count = local.ga ? 1 : 0

  name        = "allow-http-site-${var.deployment}"
  description = "Allow HTTP inbound traffic"
  vpc_id      = module.vpc[0].vpc_id
}

resource "aws_security_group_rule" "allow_http_ingress" {
  count = local.ga ? 1 : 0

  type              = "ingress"
  security_group_id = aws_security_group.allow_http[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
}

resource "aws_security_group_rule" "allow_http_egress" {
  count = local.ga ? 1 : 0

  type              = "egress"
  security_group_id = aws_security_group.allow_http[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 1
  to_port           = 65535
  protocol          = "-1"
}

resource "aws_security_group" "allow_https" {
  count = local.ga ? 1 : 0

  name        = "allow-https-site-${var.deployment}"
  description = "Allow HTTPS inbound traffic"
  vpc_id      = module.vpc[0].vpc_id
}

resource "aws_security_group_rule" "allow_https_ingress" {
  count = local.ga ? 1 : 0

  type              = "ingress"
  security_group_id = aws_security_group.allow_https[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
}

resource "aws_security_group_rule" "allow_https_egress" {
  count = local.ga ? 1 : 0

  type              = "egress"
  security_group_id = aws_security_group.allow_https[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 1
  to_port           = 65535
  protocol          = "-1"
}


resource "aws_lb" "ga_lb" {
  count = local.ga ? 1 : 0

  name               = "ga-lb-site-${var.deployment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.allow_http[0].id, aws_security_group.allow_https[0].id]
  subnets            = module.vpc[0].public_subnets

  enable_deletion_protection = false

  access_logs {
    bucket  = aws_s3_bucket.bucket_logging.bucket
    prefix  = "ga-alb/${var.deployment}/access_logs"
    enabled = true
  }
}

# Permission for the ALB to log to the S3 bucket
resource "aws_s3_bucket_policy" "alb_logging" {
  count = local.ga ? 1 : 0

  bucket = aws_s3_bucket.bucket_logging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::127311923021:root"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${aws_s3_bucket.bucket_logging.bucket}/ga-alb/${var.deployment}/access_logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      }
    ]
  })
}

resource "aws_lb_listener" "ga_lb_listener_443" {
  count = local.ga ? 1 : 0

  load_balancer_arn = aws_lb.ga_lb[0].arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.cert.arn

  default_action {
    type = "redirect"

    redirect {
      host        = var.global_accelerator_target
      path        = "/#{path}"
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "ga_lb_listener_80" {
  count = local.ga ? 1 : 0

  load_balancer_arn = aws_lb.ga_lb[0].arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      host        = var.global_accelerator_target
      path        = "/#{path}"
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
