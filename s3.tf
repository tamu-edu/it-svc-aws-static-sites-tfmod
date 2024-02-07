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
    object_ownership = "BucketOwnerEnforced"
  }
}


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

# Enable cache invalidation on the S3 object creation of the invalidate_cache.txt file
resource "aws_s3_bucket_notification" "cache_invalidation_notification" {
  bucket = aws_s3_bucket.bucket.bucket

  lambda_function {
    lambda_function_arn = aws_lambda_function.cloudfront_cache_invalidation.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "invalidate_cache.txt"
  }

  depends_on = [ aws_lambda_permission.allow_s3_to_invoke_lambda ]
}
