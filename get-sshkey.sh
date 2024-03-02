#!/bin/bash

rm -rf cw_agent_instance
terraform output -raw private_keypair > cw_agent_instance
chmod 400 cw_agent_instance
