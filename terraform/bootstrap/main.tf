# S3-bucketnamen zijn wereldwijd uniek, niet per account. "secops-lab-tfstate" is
# vrijwel zeker al bezet door iemand anders, dus we plakken er een willekeurig
# suffix achter. random_id slaat de waarde op in de state en verandert daarna
# nooit meer, in tegenstelling tot een timestamp of uuid.
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  state_bucket_name = "${var.project_name}-tfstate-${random_id.suffix.hex}"
  lock_table_name   = "${var.project_name}-tflock"
}

# ---------------------------------------------------------------------------
# State-bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "tfstate" {
  bucket = local.state_bucket_name
}

# Versioning: elke apply overschrijft terraform.tfstate. Zonder versioning is een
# corrupte of half-geschreven state definitief weg en mag je alles handmatig
# importeren. Met versioning rol je terug naar de vorige versie.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Encryptie met de door AWS beheerde KMS-sleutel (alias/aws/s3) in plaats van
# kale AES256. Reden: tfsec en checkov eisen aws:kms, en deze sleutel kost geen
# 1 dollar per maand zoals een eigen CMK. bucket_key_enabled beperkt het aantal
# KMS-calls (en dus de kosten) tot vrijwel nul.
resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# De state bevat resource-ID's, ARN's en soms secrets in platte tekst. Deze vier
# vlaggen samen maken het onmogelijk om de bucket per ongeluk publiek te zetten,
# ook niet via een losse bucket policy of ACL later.
resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACL's zijn de oude toegangslaag van S3. BucketOwnerEnforced zet ze helemaal uit,
# zodat toegang alleen nog via IAM en de bucket policy loopt. Eén mechanisme om te
# controleren in plaats van drie.
resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Versioning zonder opruimregel laat de bucket eindeloos groeien. 90 dagen is ruim
# genoeg om een fout te ontdekken, en houdt de opslag binnen de free tier (5 GB).
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "expire-noncurrent-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.tfstate]
}

# ---------------------------------------------------------------------------
# Locktable
# ---------------------------------------------------------------------------

# Zonder lock kunnen twee gelijktijdige applies (jij lokaal, CI in de pipeline)
# dezelfde state overschrijven. Terraform claimt een rij met LockID en geeft die
# pas vrij als de apply klaar is. De naam LockID en het type string liggen vast,
# dat is geen keuze maar een eis van Terraform.
resource "aws_dynamodb_table" "tflock" {
  # checkov:skip=CKV_AWS_119: de locktable bevat alleen lock-ID's en state-checksums, geen gevoelige data; een tweede CMK ($1/mnd) voegt hier geen echte beveiliging toe
  name         = local.lock_table_name
  billing_mode = "PAY_PER_REQUEST" # geen vaste capaciteit reserveren, je betaalt per lock
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }
}
