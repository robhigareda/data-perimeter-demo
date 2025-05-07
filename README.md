# AWS Data Perimeter Demo Solution

This repository contains a complete AWS data perimeter solution that demonstrates how to restrict access to AWS services based on network origin, even within the same AWS account and organization. This is a personal project and an official AWS solution or offering. This is just something I am playing with to see if it's useful.

## Solution Overview

The data perimeter solution creates:

1. **Primary VPC (Protected by Data Perimeter)**
   - Two private subnets with EC2 instances
   - Two public subnets with NAT Gateway
   - S3 buckets accessible only from this VPC

2. **Secondary VPC (Outside Data Perimeter)**
   - One public subnet with EC2 instance
   - Connected to Primary VPC via VPC peering
   - Cannot access protected resources despite having network connectivity

3. **Data Perimeter Controls**
   - VPC endpoints with restrictive policies
   - Service Control Policies (SCPs)
   - Network ACLs and security groups
   - CloudWatch monitoring and CloudTrail

## Prerequisites

- AWS CLI installed and configured with administrator access
- An AWS Organizations management account
- S3 bucket to store CloudFormation templates
- Organization ID (format: o-xxxxxxxxxx)

## Deployment Instructions

### Step 1: Prepare the CloudFormation Templates

1. Upload all CloudFormation templates to your S3 bucket:

```bash
aws s3 cp data-perimeter-demo-part1.yaml s3://your-bucket-name/
aws s3 cp data-perimeter-demo-part2.yaml s3://your-bucket-name/
aws s3 cp data-perimeter-demo-part3.yaml s3://your-bucket-name/
aws s3 cp data-perimeter-demo-primary.yaml s3://your-bucket-name/
```

### Step 2: Deploy the CloudFormation Stack

1. Deploy the master stack:

```bash
aws cloudformation create-stack \
  --stack-name data-perimeter-demo \
  --template-body file://data-perimeter-demo-primary.yaml \
  --parameters \
    ParameterKey=OrganizationId,ParameterValue=o-xxxxxxxxxx \
    ParameterKey=TemplateBucketName,ParameterValue=your-bucket-name \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM
```

2. Monitor the stack creation in the AWS CloudFormation console or using the AWS CLI:

```bash
aws cloudformation describe-stacks --stack-name data-perimeter-demo
```

3. Wait for the stack creation to complete (status: CREATE_COMPLETE).

### Step 3: Create and Attach Service Control Policies

1. Edit the `scp-commands.sh` script to update your Organization ID and Primary VPC ID:

```bash
# Your actual Organization ID
ORGANIZATION_ID="o-xxxxxxxxxx"

# Your actual Primary VPC ID (from CloudFormation output)
PRIMARY_VPC_ID="vpc-xxxxxxxxxxxxxxxxx"
```

2. Make the script executable and run it in your AWS Organizations management account:

```bash
chmod +x scp-commands.sh
./scp-commands.sh
```

## Testing the Data Perimeter

### Step 1: Connect to EC2 Instances

1. **Connect to Primary EC2 Instance**:
   - Go to AWS Console > EC2 > Instances
   - Select the instance named "Primary-EC2-1"
   - Click "Connect" > "Session Manager" > "Connect"

2. **Connect to Secondary EC2 Instance**:
   - Go to AWS Console > EC2 > Instances
   - Select the instance named "Secondary-EC2"
   - Click "Connect" > "Session Manager" > "Connect"

### Step 2: Test Access from Primary VPC (Should Succeed)

Run these commands on the Primary EC2 instance:

```bash
# Get your AWS account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# List all S3 buckets to find the protected bucket names
aws s3 ls | grep "pb1-" | cut -d' ' -f3 > bucket1.txt
aws s3 ls | grep "pb2-" | cut -d' ' -f3 > bucket2.txt
BUCKET1=$(cat bucket1.txt)
BUCKET2=$(cat bucket2.txt)

echo "Found buckets: $BUCKET1 and $BUCKET2"

# Test S3 access (should succeed)
aws s3 ls s3://$BUCKET1
aws s3 ls s3://$BUCKET2

# Create a test file and upload it (should succeed)
echo "This is a test file from Primary VPC" > test-primary.txt
aws s3 cp test-primary.txt s3://$BUCKET1/

# Test SSM access (should succeed)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 --region $REGION
```

### Step 3: Test Access from Secondary VPC (Should Fail)

Run these commands on the Secondary EC2 instance:

```bash
# Get your AWS account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# List all S3 buckets to find the protected bucket names
# Note: This will likely fail due to data perimeter controls, which is expected
aws s3 ls | grep "pb1-" | cut -d' ' -f3 > bucket1.txt
aws s3 ls | grep "pb2-" | cut -d' ' -f3 > bucket2.txt

# If the above fails, you'll need to manually enter the bucket names
# Replace these with the actual bucket names you found from the Primary EC2 instance
BUCKET1="pb1-[stack-uuid]-$ACCOUNT_ID"
BUCKET2="pb2-[stack-uuid]-$ACCOUNT_ID"

# Test S3 access (should fail with access denied)
aws s3 ls s3://$BUCKET1
aws s3 ls s3://$BUCKET2

# Try to upload a file (should fail with access denied)
echo "This is a test file from Secondary VPC" > test-secondary.txt
aws s3 cp test-secondary.txt s3://$BUCKET1/
```

### Step 4: Test Network Connectivity

From the Secondary EC2 instance, get the private IP of the Primary EC2 instance from the AWS Console and run:

```bash
# This should work (network connectivity exists)
ping -c 4 <Primary-EC2-1-Private-IP>
```

### Step 5: Check CloudTrail for Denied Actions

1. Go to AWS Console > CloudTrail > Event history
2. Filter for:
   - Event name: "GetObject" or "ListBucket"
   - User name: The role used by the Secondary EC2 instance
   - Error code: "AccessDenied"

## Understanding the Results

1. **Primary VPC Access**: EC2 instances in the Primary VPC can access the protected S3 buckets because they're within the data perimeter.

2. **Secondary VPC Access Denied**: EC2 instance in the Secondary VPC cannot access the protected S3 buckets, even though:
   - It's in the same AWS account
   - It's in the same AWS organization
   - It has network connectivity to the Primary VPC
   - It has the same IAM permissions

3. **Network Connectivity**: The ping test confirms that network connectivity exists between the VPCs, but the data perimeter controls prevent access to AWS services.

## Cleanup

To delete all resources created by this demo, you can use the provided cleanup script:

```bash
# Make the script executable
chmod +x cleanup.sh

# Run the cleanup script
./cleanup.sh
```

The cleanup script will:
1. Identify and detach all Service Control Policies (SCPs) created by the demo
2. Identify and detach all Resource Control Policies (RCPs) created by the demo
3. Delete all policies after detaching them
4. Optionally delete the CloudFormation stack

If you prefer to clean up manually, follow these steps:

### 1. Delete Service Control Policies (SCPs)

```bash
# Get the SCP IDs
aws organizations list-policies --filter SERVICE_CONTROL_POLICY

# For each policy, detach it from the organization root
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
aws organizations detach-policy --policy-id p-xxxxxxxxxx --target-id $ROOT_ID

# Delete each policy
aws organizations delete-policy --policy-id p-xxxxxxxxxx
```

### 2. Delete Resource Control Policies (RCPs)

```bash
# Get the RCP IDs
aws organizations list-policies --filter RESOURCE_CONTROL_POLICY

# For each policy, detach it from the organization root
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
aws organizations detach-policy --policy-id p-xxxxxxxxxx --target-id $ROOT_ID

# Delete each policy
aws organizations delete-policy --policy-id p-xxxxxxxxxx
```

### 3. Delete the CloudFormation stack

```bash
aws cloudformation delete-stack --stack-name data-perimeter-demo
```

### 4. Wait for the stack deletion to complete

You can monitor the deletion progress in the AWS CloudFormation console or using the AWS CLI:

```bash
aws cloudformation describe-stacks --stack-name data-perimeter-demo
```

## Troubleshooting

### Session Manager Connection Issues

If you can't connect to EC2 instances using Session Manager:

1. Verify that the EC2 instances have the required IAM role with the `AmazonSSMManagedInstanceCore` policy.
2. Check that the NAT Gateway is properly configured in the Primary VPC.
3. Ensure the security groups allow outbound HTTPS traffic (port 443).

### S3 Access Issues

If the Primary EC2 instance can't access the S3 buckets:

1. Verify that the VPC endpoint for S3 is properly configured.
2. Check the VPC endpoint policy to ensure it allows access from the Primary VPC.
3. Verify that the IAM role attached to the EC2 instance has S3 permissions.

### SCP Issues

If the Service Control Policies aren't working:

1. Verify that SCPs are enabled in your AWS Organization.
2. Check that the policies were successfully attached to the organization root.
3. Verify the policy content to ensure it's correctly targeting the resources.

## Additional Resources

- [AWS Organizations SCPs Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [VPC Endpoints Documentation](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html)
- [AWS Systems Manager Session Manager Documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
## Data Perimeter Controls Explained

The AWS Data Perimeter Demo implements multiple layers of security controls to restrict access to AWS resources based on network origin. Here's a detailed explanation of the policies in place:

### 1. Service Control Policies (SCPs)

SCPs are a type of organization policy that you can use to manage permissions across your AWS Organization. The following SCPs are implemented in this demo:

#### a. Deny External Access Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyExternalAccess",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
      }
    }
  }]
}
```
**Impact**: Denies access to all AWS services from principals outside your organization, preventing unauthorized external access.

#### b. Enforce VPC Endpoints Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EnforceVPCEndpoints",
    "Effect": "Deny",
    "Action": [
      "s3:*", 
      "dynamodb:*", 
      "ec2:*", 
      "logs:*", 
      "ssm:*"
    ],
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "aws:SourceVpc": "${PRIMARY_VPC_ID}"
      },
      "Bool": {
        "aws:ViaAWSService": "false"
      }
    }
  }]
}
```
**Impact**: Enforces the use of VPC endpoints for specified AWS services. This policy denies direct internet-based access to these services from the Primary VPC, requiring traffic to flow through the configured VPC endpoints.

#### c. Deny Public S3 Bucket Access Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicBuckets",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:PublicAccessBlockConfiguration/BlockPublicAcls": "true",
          "s3:PublicAccessBlockConfiguration/BlockPublicPolicy": "true",
          "s3:PublicAccessBlockConfiguration/IgnorePublicAcls": "true",
          "s3:PublicAccessBlockConfiguration/RestrictPublicBuckets": "true"
        }
      }
    },
    {
      "Sid": "DenyPublicACLs",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketAcl",
        "s3:PutObjectAcl"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write",
            "authenticated-read"
          ]
        }
      }
    }
  ]
}
```
**Impact**: Prevents S3 buckets from being configured with public access, ensuring that all S3 resources remain private.

#### d. Prevent Resource Sharing Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyResourceSharing",
    "Effect": "Deny",
    "Action": [
      "ram:CreateResourceShare",
      "ram:UpdateResourceShare",
      "ram:AssociateResourceShare"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "ram:RequestedAllowsExternalPrincipals": "false"
      }
    }
  }]
}
```
**Impact**: Prevents sharing AWS resources outside of your organization, maintaining the data perimeter boundary.

### 2. VPC Endpoint Policies

VPC endpoints provide private connectivity to AWS services without requiring internet access. The endpoint policies further restrict which principals can use these endpoints.

#### S3 VPC Endpoint Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*",
    "Principal": "*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
      },
      "StringNotEquals": {
        "aws:SourceVpc": "${SECONDARY_VPC_ID}"
      }
    }
  }]
}
```
**Impact**: This policy allows access to S3 through the VPC endpoint only if:
1. The request comes from a principal within your organization
2. The request does NOT originate from the Secondary VPC

This is a critical component of the data perimeter that prevents the Secondary VPC from accessing protected S3 buckets, even though it has network connectivity to the Primary VPC through VPC peering.

### 3. Network Controls

The solution implements several network-level controls:

1. **Network ACLs**: Restrict traffic between VPCs and to the internet
2. **Security Groups**: Control inbound and outbound traffic at the instance level
3. **VPC Peering**: Provides network connectivity between VPCs while maintaining security boundaries

### How These Controls Work Together

When a request is made to access an S3 bucket:

1. **From the Primary VPC**:
   - The request is routed through the S3 VPC endpoint
   - The VPC endpoint policy allows the request (from Primary VPC)
   - The SCPs allow the request (from within the organization)
   - The IAM policies allow the request (explicit S3 permissions)
   - **Result**: Access is granted

2. **From the Secondary VPC**:
   - The request attempts to use the S3 VPC endpoint in the Primary VPC (via VPC peering)
   - The VPC endpoint policy denies the request (from Secondary VPC)
   - **Result**: Access is denied

This multi-layered approach demonstrates how to implement a robust data perimeter that restricts access based on network origin, even within the same AWS account and organization.
## Resource Control Policies (RCPs)

In addition to Service Control Policies, Resource Control Policies provide another layer of protection by controlling access to resources directly. The following RCPs are implemented in this demo through the `rcp-commands.sh` script:

### 1. S3 Network Origin Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAccessFromOutsideVPC",
    "Effect": "Deny",
    "Principal": "*",
    "Action": [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket"
    ],
    "Resource": [
      "arn:aws:s3:::${PROTECTED_BUCKET1}",
      "arn:aws:s3:::${PROTECTED_BUCKET1}/*",
      "arn:aws:s3:::${PROTECTED_BUCKET2}",
      "arn:aws:s3:::${PROTECTED_BUCKET2}/*"
    ],
    "Condition": {
      "StringNotEquals": {
        "aws:SourceVpc": "${PRIMARY_VPC_ID}"
      }
    }
  }]
}
```
**Impact**: Denies access to the protected S3 buckets from any VPC other than the Primary VPC, enforcing network origin controls at the resource level.

### 2. S3 Encryption Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedObjectUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": [
        "arn:aws:s3:::${PROTECTED_BUCKET1}/*",
        "arn:aws:s3:::${PROTECTED_BUCKET2}/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": [
            "AES256",
            "aws:kms"
          ]
        }
      }
    },
    {
      "Sid": "DenyIncorrectEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": [
        "arn:aws:s3:::${PROTECTED_BUCKET1}/*",
        "arn:aws:s3:::${PROTECTED_BUCKET2}/*"
      ],
      "Condition": {
        "Bool": {
          "s3:x-amz-server-side-encryption": false
        }
      }
    }
  ]
}
```
**Impact**: Ensures that all objects uploaded to the protected buckets are encrypted, enhancing data protection at rest.

### 3. S3 Cross-Account Access Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAccessFromOutsideOrg",
    "Effect": "Deny",
    "Principal": "*",
    "Action": [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "s3:DeleteObject"
    ],
    "Resource": [
      "arn:aws:s3:::${PROTECTED_BUCKET1}",
      "arn:aws:s3:::${PROTECTED_BUCKET1}/*",
      "arn:aws:s3:::${PROTECTED_BUCKET2}",
      "arn:aws:s3:::${PROTECTED_BUCKET2}/*"
    ],
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
      }
    }
  }]
}
```
**Impact**: Prevents access to the protected buckets from principals outside your organization, ensuring that only trusted identities can access the data.

### 4. S3 TLS Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::${PROTECTED_BUCKET1}",
      "arn:aws:s3:::${PROTECTED_BUCKET1}/*",
      "arn:aws:s3:::${PROTECTED_BUCKET2}",
      "arn:aws:s3:::${PROTECTED_BUCKET2}/*"
    ],
    "Condition": {
      "Bool": {
        "aws:SecureTransport": "false"
      }
    }
  }]
}
```
**Impact**: Enforces the use of TLS for all S3 operations, protecting data in transit.

### How SCPs and RCPs Work Together

Service Control Policies (SCPs) and Resource Control Policies (RCPs) provide complementary protection:

1. **SCPs** control what actions principals (users/roles) can perform, regardless of their permissions
2. **RCPs** control which resources can be accessed, regardless of the principal's permissions

When both are implemented:
- Even if a principal has IAM permissions to access a resource, the SCP can block the action
- Even if a principal is allowed by SCPs to perform an action, the RCP can block access to specific resources
- Both must allow the access for it to succeed, creating a defense-in-depth approach

This dual-layer approach ensures that your data perimeter is enforced from both the identity side (SCPs) and the resource side (RCPs), creating a comprehensive security boundary.
### Step 4: Implement Resource Control Policies

After deploying the CloudFormation stacks and running the SCP commands, you can enhance your data perimeter by implementing Resource Control Policies:

```bash
# Make the script executable
chmod +x rcp-commands.sh

# Run the script and follow the prompts
./rcp-commands.sh
```

The script will:
1. Prompt you for the member account information:
   - AWS account ID where the data perimeter demo is deployed
   - AWS region where the stack is deployed
   - CloudFormation stack name
2. Use the `DataPerimeterRCPAccessRole` created by the CloudFormation stack to retrieve resource information
3. Create and attach Resource Control Policies to your organization
4. If cross-account access fails, the script will fall back to manual entry mode

This step completes your data perimeter implementation with both identity-side controls (SCPs) and resource-side controls (RCPs).
## VPC Endpoints for Session Manager

The data perimeter solution includes the following VPC endpoints to enable Session Manager functionality while maintaining the data perimeter controls:

1. **SSM Endpoint**: Allows EC2 instances to communicate with the Systems Manager service
2. **EC2 Messages Endpoint**: Required for Session Manager to send commands to the EC2 instances
3. **SSM Messages Endpoint**: Required for Session Manager to receive command outputs from EC2 instances

These endpoints ensure that all traffic between your EC2 instances and AWS services remains within the AWS network and doesn't traverse the public internet, maintaining the integrity of your data perimeter.

When the data perimeter controls are applied through SCPs and RCPs, traffic to AWS services is forced to go through these VPC endpoints rather than through the NAT Gateway to the internet. This is a key aspect of a proper data perimeter implementation.

If you encounter any issues with Session Manager connectivity after applying the data perimeter controls, verify that:

1. All three required endpoints (ssm, ec2messages, ssmmessages) are properly deployed
2. The endpoint policies allow traffic from your VPC
3. The security groups allow HTTPS traffic (port 443) from your EC2 instances
4. The EC2 instances have the required IAM permissions for Session Manager
