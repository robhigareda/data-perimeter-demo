#!/bin/bash
# Script to create and attach Resource Control Policies (RCPs) for the data perimeter demo
# Run this script after deploying the CloudFormation stacks and after running scp-commands.sh

# Get Organization ID
ORGANIZATION_ID=$(aws organizations describe-organization --query 'Organization.Id' --output text)
echo "Organization ID: $ORGANIZATION_ID"

# Prompt for member account information
echo "Please enter the AWS account ID where the data perimeter demo is deployed:"
read MEMBER_ACCOUNT_ID
echo "Member Account ID: $MEMBER_ACCOUNT_ID"

echo "Please enter the AWS region where the data perimeter demo is deployed:"
read REGION
echo "Region: $REGION"

echo "Please enter the CloudFormation stack name (default: data-perimeter-demo):"
read STACK_NAME
STACK_NAME=${STACK_NAME:-data-perimeter-demo}
echo "Stack Name: $STACK_NAME"

# Assume role in member account
echo "Assuming role in member account for CloudFormation access..."
ROLE_ARN="arn:aws:iam::${MEMBER_ACCOUNT_ID}:role/DataPerimeterRCPAccessRole"
echo "Role ARN: $ROLE_ARN"

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq is not installed. Using alternative method for parsing JSON."
    CREDENTIALS=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name RCPSession)
    
    # Parse credentials without jq
    AWS_ACCESS_KEY_ID=$(echo "$CREDENTIALS" | grep -o '"AccessKeyId": "[^"]*' | cut -d'"' -f4)
    AWS_SECRET_ACCESS_KEY=$(echo "$CREDENTIALS" | grep -o '"SecretAccessKey": "[^"]*' | cut -d'"' -f4)
    AWS_SESSION_TOKEN=$(echo "$CREDENTIALS" | grep -o '"SessionToken": "[^"]*' | cut -d'"' -f4)
else
    CREDENTIALS=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name RCPSession --query 'Credentials' --output json)
    
    # Extract credentials using jq
    AWS_ACCESS_KEY_ID=$(echo $CREDENTIALS | jq -r '.AccessKeyId')
    AWS_SECRET_ACCESS_KEY=$(echo $CREDENTIALS | jq -r '.SecretAccessKey')
    AWS_SESSION_TOKEN=$(echo $CREDENTIALS | jq -r '.SessionToken')
fi

# Check if assume-role was successful
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ] || [ -z "$AWS_SESSION_TOKEN" ]; then
  echo "Failed to assume role. Please check the account ID and ensure the DataPerimeterRCPAccessRole exists."
  echo "Would you like to enter the resource information manually? (y/n)"
  read MANUAL_ENTRY
  
  if [[ $MANUAL_ENTRY == "y" || $MANUAL_ENTRY == "Y" ]]; then
    echo "Please enter the Primary VPC ID:"
    read PRIMARY_VPC_ID
    echo "Primary VPC ID: $PRIMARY_VPC_ID"
    
    echo "Please enter the first protected S3 bucket name:"
    read PROTECTED_BUCKET1
    echo "Protected Bucket 1: $PROTECTED_BUCKET1"
    
    echo "Please enter the second protected S3 bucket name:"
    read PROTECTED_BUCKET2
    echo "Protected Bucket 2: $PROTECTED_BUCKET2"
  else
    echo "Exiting script."
    exit 1
  fi
else
  # Export temporary credentials
  export AWS_ACCESS_KEY_ID
  export AWS_SECRET_ACCESS_KEY
  export AWS_SESSION_TOKEN

  # Get CloudFormation outputs
  echo "Getting outputs from CloudFormation stack: $STACK_NAME"
  PRIMARY_VPC_ID=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION \
    --query "Stacks[0].Outputs[?OutputKey=='PrimaryVPCId'].OutputValue" --output text)
  echo "Primary VPC ID: $PRIMARY_VPC_ID"

  PROTECTED_BUCKET1=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION \
    --query "Stacks[0].Outputs[?OutputKey=='ProtectedBucket1Name'].OutputValue" --output text)
  echo "Protected Bucket 1: $PROTECTED_BUCKET1"

  PROTECTED_BUCKET2=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION \
    --query "Stacks[0].Outputs[?OutputKey=='ProtectedBucket2Name'].OutputValue" --output text)
  echo "Protected Bucket 2: $PROTECTED_BUCKET2"

  # Clear the assumed role credentials
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
fi

# Verify we have all required information
if [ -z "$PRIMARY_VPC_ID" ] || [ -z "$PROTECTED_BUCKET1" ] || [ -z "$PROTECTED_BUCKET2" ]; then
  echo "Missing required information. Please ensure all values are provided."
  exit 1
fi

# Function to check if a policy type is enabled
check_policy_type_enabled() {
  local policy_type=$1
  local status=$(aws organizations list-roots --query "Roots[0].PolicyTypes[?Type=='$policy_type'].Status" --output text)
  
  if [ "$status" == "ENABLED" ]; then
    echo "true"
  else
    echo "false"
  fi
}

# Function to enable a policy type
enable_policy_type() {
  local policy_type=$1
  local root_id=$2
  
  echo "Enabling $policy_type in the organization..."
  aws organizations enable-policy-type --root-id $root_id --policy-type $policy_type
  echo "$policy_type enabled successfully."
}

# Function to get policy ID if it exists
get_policy_id() {
  local policy_name=$1
  local policy_type=$2
  
  aws organizations list-policies --filter $policy_type --query "Policies[?Name=='$policy_name'].Id" --output text --no-cli-pager
}

# Function to detach policy from all targets
detach_policy_from_all_targets() {
  local policy_id=$1
  
  echo "Detaching policy from all targets..."
  for target in $(aws organizations list-targets-for-policy --policy-id $policy_id --query 'Targets[].TargetId' --output text --no-cli-pager 2>/dev/null); do
    echo "Detaching from target: $target"
    aws organizations detach-policy --policy-id $policy_id --target-id $target --no-cli-pager
  done
}

# Get the organization root ID
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
echo "Organization Root ID: $ROOT_ID"

# Check if RCP is enabled, enable if not
RCP_ENABLED=$(check_policy_type_enabled "RESOURCE_CONTROL_POLICY")
if [ "$RCP_ENABLED" == "false" ]; then
  enable_policy_type "RESOURCE_CONTROL_POLICY" $ROOT_ID
else
  echo "Resource Control Policies are already enabled."
fi

# Create or update the S3 bucket network origin policy
echo "Creating/updating S3 bucket network origin policy..."
S3_NETWORK_ORIGIN_POLICY_ID=$(get_policy_id "s3-network-origin" "RESOURCE_CONTROL_POLICY")

if [ -n "$S3_NETWORK_ORIGIN_POLICY_ID" ]; then
  echo "Policy already exists with ID: $S3_NETWORK_ORIGIN_POLICY_ID"
  
  # Detach policy first to ensure it can be updated
  detach_policy_from_all_targets $S3_NETWORK_ORIGIN_POLICY_ID
  
  # Update existing policy
  aws organizations update-policy \
    --policy-id $S3_NETWORK_ORIGIN_POLICY_ID \
    --description "Restrict S3 bucket access based on network origin" \
    --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyAccessFromOutsideVPC\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}\",\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"${PRIMARY_VPC_ID}\"}}}]}" \
    --no-cli-pager
else
  # Create new policy
  S3_NETWORK_ORIGIN_POLICY_ID=$(aws organizations create-policy \
    --name s3-network-origin \
    --description "Restrict S3 bucket access based on network origin" \
    --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyAccessFromOutsideVPC\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}\",\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"${PRIMARY_VPC_ID}\"}}}]}" \
    --type RESOURCE_CONTROL_POLICY \
    --query 'Policy.PolicySummary.Id' \
    --output text \
    --no-cli-pager)
fi

echo "S3 Network Origin Policy ID: $S3_NETWORK_ORIGIN_POLICY_ID"

# Create or update the S3 bucket encryption policy
echo "Creating/updating S3 bucket encryption policy..."
S3_ENCRYPTION_POLICY_ID=$(get_policy_id "s3-encryption-required" "RESOURCE_CONTROL_POLICY")

if [ -n "$S3_ENCRYPTION_POLICY_ID" ]; then
  echo "Policy already exists with ID: $S3_ENCRYPTION_POLICY_ID"
  
  # Detach policy first to ensure it can be updated
  detach_policy_from_all_targets $S3_ENCRYPTION_POLICY_ID
  
  # Update existing policy
  aws organizations update-policy \
    --policy-id $S3_ENCRYPTION_POLICY_ID \
    --description "Enforce encryption for S3 buckets" \
    --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyUnencryptedObjectUploads\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"StringNotEquals\":{\"s3:x-amz-server-side-encryption\":[\"AES256\",\"aws:kms\"]}}},{\"Sid\":\"DenyIncorrectEncryptionHeader\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"Bool\":{\"s3:x-amz-server-side-encryption\":false}}}]}" \
    --no-cli-pager
else
  # Create new policy
  S3_ENCRYPTION_POLICY_ID=$(aws organizations create-policy \
    --name s3-encryption-required \
    --description "Enforce encryption for S3 buckets" \
    --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyUnencryptedObjectUploads\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"StringNotEquals\":{\"s3:x-amz-server-side-encryption\":[\"AES256\",\"aws:kms\"]}}},{\"Sid\":\"DenyIncorrectEncryptionHeader\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"Bool\":{\"s3:x-amz-server-side-encryption\":false}}}]}" \
    --type RESOURCE_CONTROL_POLICY \
    --query 'Policy.PolicySummary.Id' \
    --output text \
    --no-cli-pager)
fi

echo "S3 Encryption Policy ID: $S3_ENCRYPTION_POLICY_ID"

# Create or update the S3 bucket cross-account access policy
echo "Creating/updating S3 bucket cross-account access policy..."
S3_CROSS_ACCOUNT_POLICY_ID=$(get_policy_id "s3-cross-account-access" "RESOURCE_CONTROL_POLICY")

if [ -n "$S3_CROSS_ACCOUNT_POLICY_ID" ]; then
  echo "Policy already exists with ID: $S3_CROSS_ACCOUNT_POLICY_ID"
  
  # Detach policy first to ensure it can be updated
  detach_policy_from_all_targets $S3_CROSS_ACCOUNT_POLICY_ID
  
  # Update existing policy
  aws organizations update-policy \
    --policy-id $S3_CROSS_ACCOUNT_POLICY_ID \
    --description "Restrict S3 bucket access to principals within the organization" \
    --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyAccessFromOutsideOrg\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:ListBucket\",\"s3:DeleteObject\"],\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}\",\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"${ORGANIZATION_ID}\"}}}]}" \
    --no-cli-pager
else
  # Create new policy
  S3_CROSS_ACCOUNT_POLICY_ID=$(aws organizations create-policy \
    --name s3-cross-account-access \
    --description "Restrict S3 bucket access to principals within the organization" \
    --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyAccessFromOutsideOrg\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:ListBucket\",\"s3:DeleteObject\"],\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}\",\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"${ORGANIZATION_ID}\"}}}]}" \
    --type RESOURCE_CONTROL_POLICY \
    --query 'Policy.PolicySummary.Id' \
    --output text \
    --no-cli-pager)
fi

echo "S3 Cross-Account Access Policy ID: $S3_CROSS_ACCOUNT_POLICY_ID"

# Create or update the S3 bucket TLS policy
echo "Creating/updating S3 bucket TLS policy..."
S3_TLS_POLICY_ID=$(get_policy_id "s3-tls-required" "RESOURCE_CONTROL_POLICY")

if [ -n "$S3_TLS_POLICY_ID" ]; then
  echo "Policy already exists with ID: $S3_TLS_POLICY_ID"
  
  # Detach policy first to ensure it can be updated
  detach_policy_from_all_targets $S3_TLS_POLICY_ID
  
  # Update existing policy
  aws organizations update-policy \
    --policy-id $S3_TLS_POLICY_ID \
    --description "Enforce TLS for S3 bucket access" \
    --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyInsecureTransport\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}\",\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}" \
    --no-cli-pager
else
  # Create new policy
  S3_TLS_POLICY_ID=$(aws organizations create-policy \
    --name s3-tls-required \
    --description "Enforce TLS for S3 bucket access" \
    --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyInsecureTransport\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::${PROTECTED_BUCKET1}\",\"arn:aws:s3:::${PROTECTED_BUCKET1}/*\",\"arn:aws:s3:::${PROTECTED_BUCKET2}\",\"arn:aws:s3:::${PROTECTED_BUCKET2}/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}" \
    --type RESOURCE_CONTROL_POLICY \
    --query 'Policy.PolicySummary.Id' \
    --output text \
    --no-cli-pager)
fi

echo "S3 TLS Policy ID: $S3_TLS_POLICY_ID"

# Attach policies to the organization root
echo "Attaching policies to the organization root..."
aws organizations attach-policy --policy-id $S3_NETWORK_ORIGIN_POLICY_ID --target-id $ROOT_ID --no-cli-pager
aws organizations attach-policy --policy-id $S3_ENCRYPTION_POLICY_ID --target-id $ROOT_ID --no-cli-pager
aws organizations attach-policy --policy-id $S3_CROSS_ACCOUNT_POLICY_ID --target-id $ROOT_ID --no-cli-pager
aws organizations attach-policy --policy-id $S3_TLS_POLICY_ID --target-id $ROOT_ID --no-cli-pager

echo "Resource Control Policies created/updated and attached successfully!"
echo ""
echo "Policy IDs:"
echo "S3 Network Origin Policy: $S3_NETWORK_ORIGIN_POLICY_ID"
echo "S3 Encryption Policy: $S3_ENCRYPTION_POLICY_ID"
echo "S3 Cross-Account Access Policy: $S3_CROSS_ACCOUNT_POLICY_ID"
echo "S3 TLS Policy: $S3_TLS_POLICY_ID"
