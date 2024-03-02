#!/bin/bash

sudo yum update -y
# Install agent for AL2
sudo yum install amazon-cloudwatch-agent -y
sudo amazon-linux-extras install nginx1
sudo systemctl start nginx

sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c ssm:${cw-configuration-path}