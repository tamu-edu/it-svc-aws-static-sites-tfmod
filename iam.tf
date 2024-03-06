locals {
  site_name_dashes = replace(var.site_settings.top_level_domain, ".", "-")

  iam_user_name = substr("iam-static-website-deployment-${var.site_settings.top_level_domain}-${var.deployment}", 0, 64)
}


resource "aws_iam_user" "user" {
  name = local.iam_user_name
  path = "/cascade/"
}

resource "aws_iam_user_policy" "policy" {
  name     = "iam-${local.site_name_dashes}-cloudfront-with-lambda-edge"
  user     = aws_iam_user.user.name

  policy = jsonencode(
    {
      Version = "2012-10-17"
      Statement = [
        {
          Action = "*"
          Effect = "Allow"
          Resource = [
            "arn:aws:s3:::${aws_s3_bucket.bucket.bucket}/*",
            "arn:aws:s3:::${aws_s3_bucket.bucket.bucket}"
          ]
        },
        {
          Action = [
            "s3:ListAllMyBuckets",
            "s3:GetBucketLocation"
          ]
          Effect   = "Allow"
          Resource = "*"
        }
      ]
  })
}

resource "aws_iam_access_key" "key" {
  user = aws_iam_user.user.name
}


