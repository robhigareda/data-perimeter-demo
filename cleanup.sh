#!/bin/bash
# Cleanup script for the AWS Data Perimeter Demo
# This script removes all resources created by the demo, including SCPs and RCPs

echo "Starting cleanup of AWS Data Perimeter Demo resources..."

# Function to get policy IDs by name and type
get_policy_id() {
  local policy_name=$1
  local policy_type=$2
  
  aws organizations list-policies --filter $policy_type --query "Policies[?Name=='$policy_name'].Id" --output text --no-cli-pager
}

# Function to detach and delete a policy
detach_and_delete_policy() {
  local policy_id=$1
  local policy_name=$2
  
  if [ -n "$policy_id" ]; then
    echo "Found $policy_name policy with ID: $policy_id"
    
    # Get the organization root ID
    ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
    
    # Detach policy from all targets
    echo "Detaching $policy_name policy from all targets..."
    for target in $(aws organizations list-targets-for-policy --policy-id $policy_id --query 'Targets[].TargetId' --output text --no-cli-pager 2>/dev/null); do
      echo "Detaching from target: $target"
      aws organizations detach-policy --policy-id $policy_id --target-id $target --no-cli-pager
    done
    
    # Delete the policy
    echo "Deleting $policy_name policy..."
    aws organizations delete-policy --policy-id $policy_id
    echo "$policy_name policy deleted successfully."
  else
    echo "$policy_name policy not found."
  fi
}

# Cleanup Service Control Policies (SCPs)
echo "Cleaning up Service Control Policies..."

# Get SCP IDs
DENY_EXTERNAL_POLICY_ID=$(get_policy_id "deny-external-access" "SERVICE_CONTROL_POLICY")
DENY_PUBLIC_S3_POLICY_ID=$(get_policy_id "deny-public-s3" "SERVICE_CONTROL_POLICY")
ENFORCE_VPC_ENDPOINTS_POLICY_ID=$(get_policy_id "enforce-vpc-endpoints" "SERVICE_CONTROL_POLICY")
PREVENT_RESOURCE_SHARING_POLICY_ID=$(get_policy_id "prevent-resource-sharing" "SERVICE_CONTROL_POLICY")

# Detach and delete SCPs
detach_and_delete_policy "$DENY_EXTERNAL_POLICY_ID" "Deny External Access"
detach_and_delete_policy "$DENY_PUBLIC_S3_POLICY_ID" "Deny Public S3"
detach_and_delete_policy "$ENFORCE_VPC_ENDPOINTS_POLICY_ID" "Enforce VPC Endpoints"
detach_and_delete_policy "$PREVENT_RESOURCE_SHARING_POLICY_ID" "Prevent Resource Sharing"

# Cleanup Resource Control Policies (RCPs)
echo "Cleaning up Resource Control Policies..."

# Get RCP IDs
S3_NETWORK_ORIGIN_POLICY_ID=$(get_policy_id "s3-network-origin" "RESOURCE_CONTROL_POLICY")
S3_ENCRYPTION_POLICY_ID=$(get_policy_id "s3-encryption-required" "RESOURCE_CONTROL_POLICY")
S3_CROSS_ACCOUNT_POLICY_ID=$(get_policy_id "s3-cross-account-access" "RESOURCE_CONTROL_POLICY")
S3_TLS_POLICY_ID=$(get_policy_id "s3-tls-required" "RESOURCE_CONTROL_POLICY")

# Detach and delete RCPs
detach_and_delete_policy "$S3_NETWORK_ORIGIN_POLICY_ID" "S3 Network Origin"
detach_and_delete_policy "$S3_ENCRYPTION_POLICY_ID" "S3 Encryption Required"
detach_and_delete_policy "$S3_CROSS_ACCOUNT_POLICY_ID" "S3 Cross-Account Access"
detach_and_delete_policy "$S3_TLS_POLICY_ID" "S3 TLS Required"

# Delete CloudFormation stack
echo "Do you want to delete the CloudFormation stack? (y/n)"
read DELETE_STACK

if [[ $DELETE_STACK == "y" || $DELETE_STACK == "Y" ]]; then
  echo "Please enter the CloudFormation stack name (default: data-perimeter-demo):"
  read STACK_NAME
  STACK_NAME=${STACK_NAME:-data-perimeter-demo}
  
  echo "Deleting CloudFormation stack: $STACK_NAME"
  aws cloudformation delete-stack --stack-name $STACK_NAME
  
  echo "Waiting for stack deletion to complete..."
  aws cloudformation wait stack-delete-complete --stack-name $STACK_NAME
  
  if [ $? -eq 0 ]; then
    echo "Stack deletion completed successfully."
  else
    echo "Stack deletion may still be in progress. Please check the AWS CloudFormation console."
  fi
else
  echo "Skipping CloudFormation stack deletion."
fi

echo "Cleanup completed!"
