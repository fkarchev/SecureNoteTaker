module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"

  identifier = "secure-notes-db"

  engine               = "mysql"
  engine_version       = "8.0"
  family               = "mysql8.0"
  major_engine_version = "8.0"
  instance_class       = "db.t4g.micro"

  allocated_storage = 20

  db_name  = "secure_notes"
  username = "api_user"
  # SECURITY: In a real scenario, this password should be generated securely or retrieved from Secrets Manager
  password = "api_password_123"
  port     = 3306

  multi_az               = false
  subnet_ids             = module.vpc.private_subnets
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  # SECURITY: Ensure the database is not exposed to the public internet
  publicly_accessible = false
  skip_final_snapshot = true
}

resource "aws_security_group" "db_sg" {
  name        = "secure-notes-db-sg"
  description = "Allow inbound traffic from EKS"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "MySQL from EKS nodes"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    # SECURITY: Only allow traffic from the EKS nodes security group
    security_groups = [module.eks.node_security_group_id]
  }
}
