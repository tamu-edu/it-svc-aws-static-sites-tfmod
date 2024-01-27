#terraform {
#  required_providers {
#    aws = {
#      source  = "hashicorp/aws"
#      version = ">= 5.0"
#    }
#
#    archive = {
#      source  = "hashicorp/archive"
#      version = ">= 2.4.1"
#    }
#
#    external = {
#      source  = "hashicorp/external"
#      version = ">= 2.3.2"
#    }
#
#    infoblox = {
#      source = "infobloxopen/infoblox"
#      version = "2.5.0"
#    }
#
#    onepassword = {
#      source  = "1Password/onepassword"
#      version = "1.4.0"
#    }
#  }
#}

terraform {
  required_providers {
    infoblox = {
      source = "infobloxopen/infoblox"
    }

    onepassword = {
      source  = "1Password/onepassword"
    }
  }
}

#provider "onepassword" {
#  url = var.onepassword_url
#}

data "aws_caller_identity" "current" {}
