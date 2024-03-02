# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

/**
1. VPC with 2 public subnet and 2 private subnet
2. Autoscaling Group in private subnet: EC2 instance with cloudWatch agent managed by SSM service
  configuration file to match log group with each instance in ASG
  - Config CloudWatch group to receive application log from instance (Nginx logs)
  - save CW configuration to ssm parameter store
  - create lauch template to Add user_data to download cloudwatch agent and configuration from ssm
  - create ASG and scaling policy
  - Setup VPC private link for cloudwatch endpoint => add dns link to cw configuration   
4. CloudWatch alarm on specific error and send notification to Slack
  - setup metric filter and SNS topic 
  - Lambda function to send request to weekhook
6. Config ALB + ACM and Cloudflare DNS
  - Route 53
  - TODO: ALB => nginx server
*/

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  required_version = "~> 1.3"
}

provider "aws" {}

# Filter out local zones, which are not currently supported 
# with managed node groups
# Terraform will fetch and filter all Availability Zones in the default Region of AWS CLI
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_region" "current" {}

# The locals block will be used to save some common information and ca be re-use in another place
locals {
  vpc = {
    name            = "My VPC"
    cidr            = "172.31.0.0/16"
    public_subnets  = ["172.31.1.0/24", "172.31.2.0/24"]
    private_subnets = ["172.31.3.0/24", "172.31.4.0/24"]
  }
}

############### VPC ###############
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"

  name            = local.vpc.name
  cidr            = local.vpc.cidr
  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  public_subnets  = local.vpc.public_subnets
  private_subnets = local.vpc.private_subnets

  enable_nat_gateway      = true
  map_public_ip_on_launch = true
}

resource "aws_ec2_instance_connect_endpoint" "lab_instance" {
  subnet_id          = module.vpc.private_subnets[0]
  security_group_ids = [module.instance_connect_sg.security_group_id]
}

resource "aws_vpc_endpoint" "cw-endpoint" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.logs"
  vpc_endpoint_type = "Interface"

  security_group_ids = [module.vpc_endpoint_sg.security_group_id]
  subnet_ids         = module.vpc.private_subnets
}

############### Security Group ###############
module "instance_connect_sg" {
  source      = "terraform-aws-modules/security-group/aws"
  name        = "instance_connect_sg"
  description = "instance_connect_sg"
  vpc_id      = module.vpc.vpc_id

  egress_rules       = ["all-all"]
  egress_cidr_blocks = [local.vpc.cidr]
}

module "alb_sg" {
  source      = "terraform-aws-modules/security-group/aws"
  name        = "alb_sg"
  description = "alb_sg"
  vpc_id      = module.vpc.vpc_id

  egress_rules       = ["all-all"]
  egress_cidr_blocks = ["0.0.0.0/0"]

  ingress_rules       = ["http-80-tcp"]
  ingress_cidr_blocks = ["0.0.0.0/0"]
}

module "instance_sg" {
  source = "terraform-aws-modules/security-group/aws"

  name        = "lab_instance-sg"
  description = "lab_instance-sg"
  vpc_id      = module.vpc.vpc_id

  ingress_with_source_security_group_id = [
    {
      # Allow traffic from the Instance Connect Endpoint
      source_security_group_id = module.instance_connect_sg.security_group_id
      rule                     = "all-all"
    },
    {
      # Allow traffic from the Application Load Balancer
      source_security_group_id = module.alb_sg.security_group_id
      rule                     = "http-80-tcp"
    }
  ]

  egress_rules       = ["all-all"]
  egress_cidr_blocks = ["0.0.0.0/0"]
}

module "vpc_endpoint_sg" {
  source = "terraform-aws-modules/security-group/aws"

  name        = "SG VPC Cloudwatch Endpoint"
  description = "SG VPC Cloudwatch Endpoint"
  vpc_id      = module.vpc.vpc_id

  ingress_rules       = ["all-all"]
  ingress_cidr_blocks = [local.vpc.cidr]
}

############### Keypair ###############
resource "tls_private_key" "cw_agent_instance" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "cw_agent_instance" {
  key_name   = "cw_agent_instance"
  public_key = tls_private_key.cw_agent_instance.public_key_openssh
}

# Output: "terraform output -raw private_keypair > cw_agent_instance" to save private key
output "private_keypair" {
  value     = tls_private_key.cw_agent_instance.private_key_pem
  sensitive = true
}


############### IAM role ###############
resource "aws_iam_role" "instance_connect_role" {
  name = "instance-connect-iam-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  inline_policy {
    name = "instnace-connect-role-inline-policy"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          "Sid" : "EC2InstanceConnect",
          "Action" : "ec2-instance-connect:OpenTunnel",
          "Effect" : "Allow",
          "Resource" : aws_ec2_instance_connect_endpoint.lab_instance.arn
        },
        {
          "Sid" : "SSHPublicKey",
          "Effect" : "Allow",
          "Action" : "ec2-instance-connect:SendSSHPublicKey",
          "Resource" : "*"
        }
      ]
    })
  }

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
  ]

  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_instance_profile" "instance_connect_profile" {
  name = "instance_connect_role-profile"
  role = aws_iam_role.instance_connect_role.name
}

############### Aamazon Machine Image ###############
data "aws_ami" "linux_amazon" {
  most_recent = true

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

############### Application LoadBalancer ###############
resource "aws_lb" "lab_alb" {
  name               = "lab-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [module.alb_sg.security_group_id]
  subnets            = module.vpc.public_subnets

  enable_deletion_protection = true

  access_logs {
    bucket  = module.s3_bucket_for_logs.s3_bucket_id
    prefix  = ""
    enabled = true
  }
}

resource "aws_lb_target_group" "lab_instance" {
  name     = "lab-instance"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id
}


resource "aws_lb_listener" "demo-alb-listener" {
  load_balancer_arn = aws_lb.lab_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lab_instance.arn
  }
}

resource "aws_autoscaling_attachment" "web_asg_attachment" {
  autoscaling_group_name = aws_autoscaling_group.web_asg.id
  lb_target_group_arn    = aws_lb_target_group.lab_instance.arn
}

############### AutoScaling Group ###############
resource "aws_autoscaling_group" "web_asg" {
  desired_capacity = 1
  max_size         = 2
  min_size         = 1

  launch_template {
    id      = aws_launch_template.web_instance_template.id
    version = "$Latest"
  }

  vpc_zone_identifier = module.vpc.private_subnets
}

resource "aws_launch_template" "web_instance_template" {
  name_prefix   = "web_instance_template"
  image_id      = data.aws_ami.linux_amazon.id
  instance_type = "t3.micro"
  key_name      = aws_key_pair.cw_agent_instance.key_name
  user_data     = base64encode(templatefile("user-data.sh", { cw-configuration-path = "cw-agent-configuration-file" }))

  vpc_security_group_ids = [module.instance_sg.security_group_id]

  iam_instance_profile {
    name = aws_iam_instance_profile.instance_connect_profile.name
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "web_instance"
    }
  }
}

resource "aws_autoscaling_policy" "cpu" {
  name                      = "cpu-auto-scaling"
  autoscaling_group_name    = aws_autoscaling_group.web_asg.name
  policy_type               = "TargetTrackingScaling"
  estimated_instance_warmup = 60
  enabled                   = true

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }

    target_value = 70
  }
}


############### CloudWatch ###############
resource "aws_cloudwatch_log_group" "lab_instance" {
  name = "lab_instance"
}

############### SSM parameter store ###############
resource "aws_ssm_parameter" "cw-agent-configuration" {
  name = "cw-agent-configuration-file"
  type = "String"
  value = templatefile("cw-agent-configuration.json",
    {
      cw-log-group      = "lab_instance",
      endpoint_override = aws_vpc_endpoint.cw-endpoint.dns_entry[0].dns_name
  })
}

############### Route53 ###############
resource "aws_route53_zone" "fcj" {
  name = "fcj.com"

  vpc {
    vpc_id = module.vpc.vpc_id
  }
}

resource "aws_route53_record" "apex" {
  zone_id = aws_route53_zone.fcj.zone_id
  name    = "fcj.com"
  type    = "A"

  alias {
    name                   = aws_lb.lab_alb.dns_name
    zone_id                = aws_lb.lab_alb.zone_id
    evaluate_target_health = true
  }
}

############### S3 ###############
resource "random_pet" "s3_bucket" {}

module "s3_bucket_for_logs" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "my-s3-bucket-for-logs-lab-${random_pet.s3_bucket.id}"
  acl    = "log-delivery-write"

  # Allow deletion of non-empty bucket
  force_destroy = true

  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  attach_elb_log_delivery_policy = true # Required for ALB logs
  attach_lb_log_delivery_policy  = true # Required for ALB/NLB logs
}