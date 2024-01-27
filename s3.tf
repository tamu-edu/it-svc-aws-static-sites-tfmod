resource "aws_s3_bucket" "bucket" {
  bucket        = "site-${local.site_name_dashes}-${var.deployment}"
  force_destroy = var.allow_bucket_force_destroy
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}


#resource "aws_s3_bucket_website_configuration" "bucket" {
#  bucket = aws_s3_bucket.bucket.id
#
#  index_document {
#    suffix = "index.html"
#  }
#
#  error_document {
#    key = "error.html"
#  }
#}

#resource "aws_s3_bucket_public_access_block" "bucket" {
#  bucket = aws_s3_bucket.bucket.id
#
#  block_public_acls       = false
#  block_public_policy     = false
#  ignore_public_acls      = false
#  restrict_public_buckets = false
#}

resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "bucket_logging" {
  bucket        = "site-${local.site_name_dashes}-${var.deployment}-logs"
  force_destroy = var.allow_bucket_force_destroy
}

resource "aws_s3_bucket_lifecycle_configuration" "bucket_logging" {
  bucket = aws_s3_bucket.bucket_logging.id

  rule {
    id     = "RetentionPolicyinDays"
    status = "Enabled"
    expiration {
      days = var.log_expiration
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_logging" {
  bucket = aws_s3_bucket.bucket_logging.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_logging" {
  bucket = aws_s3_bucket.bucket_logging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "bucket_logging" {
  bucket = aws_s3_bucket.bucket_logging.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_policy" "site_bucket_policy" {
  bucket = aws_s3_bucket.bucket.bucket

  policy = jsonencode(
    {
      Version = "2012-10-17"
      Id      = "BUCKETPOLICY"
      Statement = [
        #{
        #  Sid       = "PublicAccess"
        #  Effect    = "Allow"
        #  Principal = "*"
        #  Action = [
        #    "s3:GetObject",
        #    "s3:GetObjectVersion",
        #    "s3:GetBucketLocation",
        #    "s3:ListBucket"
        #  ]
        #  Resource = [
        #    "arn:aws:s3:::${aws_s3_bucket.bucket.bucket}/*",
        #    "arn:aws:s3:::${aws_s3_bucket.bucket.bucket}"
        #  ]
        #},
        {
          Sid    = "AllowCloudFrontServicePrincipal"
          Effect = "Allow"
          Principal = {
            Service = "cloudfront.amazonaws.com"
          }
          Action = [
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:GetBucketLocation",
            "s3:ListBucket"
          ]
          Resource = [
            "arn:aws:s3:::${aws_s3_bucket.bucket.bucket}",
            "arn:aws:s3:::${aws_s3_bucket.bucket.bucket}/*"
          ]
          Condition = {
            StringEquals = {
              "AWS:SourceArn" = aws_cloudfront_distribution.site.arn
            }
          }
        }
      ]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.bucket
  ]
}
