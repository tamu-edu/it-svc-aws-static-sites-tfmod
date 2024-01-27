locals {
  test_index = <<EOF
<!DOCTYPE html>
<html>
    <head>
        <title>Hello World (${var.deployment})!</title>
    </head>
    <body>
        <h1>Hello World (${var.deployment})!</h1>
    </body>
</html>
EOF
}

# Only ever write this once (and then ignore it)
resource "aws_s3_object" "test_index" {
  bucket       = aws_s3_bucket.bucket.bucket
  key          = "index.html"
  #acl          = "public-read"
  content      = local.test_index
  content_type = "text/html"

  etag = md5(local.test_index)

  lifecycle {
    ignore_changes = all
  }
}
