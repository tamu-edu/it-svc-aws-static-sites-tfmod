# Store the S3 access keys in 1password

data "onepassword_vault" "s3_vault" {
  name = var.onepassword_vault
}

resource "onepassword_item" "s3_credentials" {
  vault    = data.onepassword_vault.s3_vault.uuid
  title    = local.domain
  category = "login"
  username = aws_iam_access_key.key.id
  password = aws_iam_access_key.key.secret
  url      = local.domain

  section {
    label = "notes"
    field {
      label = "S3 Bucket"
      value = aws_s3_bucket.bucket.bucket
    }
  }
}
