#!/bin/bash
# Script to create and attach Service Control Policies (SCPs) for the data perimeter demo
# Run this script after deploying the CloudFormation stacks

# Your actual Organization ID
ORGANIZATION_ID="o-xxxxxxx"

# Your actual Primary VPC ID (from CloudFormation output)
PRIMARY_VPC_ID="vpc-xxxxxxxxxxx"

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

# Get the organization root ID
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
echo "Organization Root ID: $ROOT_ID"

# Check if SCP is enabled, enable if not
SCP_ENABLED=$(check_policy_type_enabled "SERVICE_CONTROL_POLICY")
if [ "$SCP_ENABLED" == "false" ]; then
  enable_policy_type "SERVICE_CONTROL_POLICY" $ROOT_ID
else
  echo "Service Control Policies are already enabled."
fi

# Check if RCP is enabled, enable if not
RCP_ENABLED=$(check_policy_type_enabled "RESOURCE_CONTROL_POLICY")
if [ "$RCP_ENABLED" == "false" ]; then
  enable_policy_type "RESOURCE_CONTROL_POLICY" $ROOT_ID
else
  echo "Resource Control Policies are already enabled."
fi

# Create the deny external access policy
echo "Creating deny external access policy..."
DENY_EXTERNAL_POLICY_ID=$(aws organizations create-policy \
  --name deny-external-access \
  --description "Deny access to AWS services from outside the organization" \
  --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyExternalAccess\",\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"${ORGANIZATION_ID}\"}}}]}" \
  --type SERVICE_CONTROL_POLICY \
  --query 'Policy.PolicySummary.Id' \
  --output text)

echo "Created policy: $DENY_EXTERNAL_POLICY_ID"

# Create the deny public S3 bucket access policy
echo "Creating deny public S3 bucket access policy..."
DENY_PUBLIC_S3_POLICY_ID=$(aws organizations create-policy \
  --name deny-public-s3 \
  --description "Deny public S3 bucket access" \
  --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyPublicBuckets\",\"Effect\":\"Deny\",\"Action\":[\"s3:PutBucketPublicAccessBlock\",\"s3:PutAccountPublicAccessBlock\"],\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:PublicAccessBlockConfiguration/BlockPublicAcls\":\"true\",\"s3:PublicAccessBlockConfiguration/BlockPublicPolicy\":\"true\",\"s3:PublicAccessBlockConfiguration/IgnorePublicAcls\":\"true\",\"s3:PublicAccessBlockConfiguration/RestrictPublicBuckets\":\"true\"}}},{\"Sid\":\"DenyPublicACLs\",\"Effect\":\"Deny\",\"Action\":[\"s3:PutBucketAcl\",\"s3:PutObjectAcl\"],\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":[\"public-read\",\"public-read-write\",\"authenticated-read\"]}}}]}" \
  --type SERVICE_CONTROL_POLICY \
  --query 'Policy.PolicySummary.Id' \
  --output text)

echo "Created policy: $DENY_PUBLIC_S3_POLICY_ID"

# Create the enforce VPC endpoints policy
echo "Creating enforce VPC endpoints policy..."
ENFORCE_VPC_ENDPOINTS_POLICY_ID=$(aws organizations create-policy \
  --name enforce-vpc-endpoints \
  --description "Enforce the use of VPC endpoints for AWS services" \
  --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"EnforceVPCEndpoints\",\"Effect\":\"Deny\",\"Action\":[\"s3:*\",\"dynamodb:*\",\"ec2:*\",\"logs:*\",\"ssm:*\"],\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:SourceVpc\":\"${PRIMARY_VPC_ID}\"},\"Bool\":{\"aws:ViaAWSService\":\"false\"}}}]}" \
  --type SERVICE_CONTROL_POLICY \
  --query 'Policy.PolicySummary.Id' \
  --output text)

echo "Created policy: $ENFORCE_VPC_ENDPOINTS_POLICY_ID"

# Create the prevent resource sharing policy
echo "Creating prevent resource sharing policy..."
PREVENT_RESOURCE_SHARING_POLICY_ID=$(aws organizations create-policy \
  --name prevent-resource-sharing \
  --description "Prevent sharing resources outside the organization" \
  --content "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyResourceSharing\",\"Effect\":\"Deny\",\"Action\":[\"ram:CreateResourceShare\",\"ram:UpdateResourceShare\",\"ram:AssociateResourceShare\"],\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"ram:RequestedAllowsExternalPrincipals\":\"false\"}}}]}" \
  --type SERVICE_CONTROL_POLICY \
  --query 'Policy.PolicySummary.Id' \
  --output text)

echo "Created policy: $PREVENT_RESOURCE_SHARING_POLICY_ID"

# Attach policies to the organization ROOT (not the organization ID)
echo "Attaching policies to the organization root..."
aws organizations attach-policy --policy-id $DENY_EXTERNAL_POLICY_ID --target-id $ROOT_ID
aws organizations attach-policy --policy-id $DENY_PUBLIC_S3_POLICY_ID --target-id $ROOT_ID
aws organizations attach-policy --policy-id $ENFORCE_VPC_ENDPOINTS_POLICY_ID --target-id $ROOT_ID
aws organizations attach-policy --policy-id $PREVENT_RESOURCE_SHARING_POLICY_ID --target-id $ROOT_ID

echo "Service Control Policies created and attached successfully!"
echo ""
echo "Policy IDs:"
echo "Deny External Access Policy: $DENY_EXTERNAL_POLICY_ID"
echo "Deny Public S3 Policy: $DENY_PUBLIC_S3_POLICY_ID"
echo "Enforce VPC Endpoints Policy: $ENFORCE_VPC_ENDPOINTS_POLICY_ID"
echo "Prevent Resource Sharing Policy: $PREVENT_RESOURCE_SHARING_POLICY_ID"
