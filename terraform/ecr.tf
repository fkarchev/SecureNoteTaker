# SECURITY: ECR repositories are private by default
resource "aws_ecr_repository" "api" {
  name                 = "secure-notes-api"
  image_tag_mutability = "MUTABLE"

  # SECURITY: Scan images for vulnerabilities when pushed
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "frontend" {
  name                 = "secure-notes-frontend"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
