# Creates a persistent set of intentionally-vulnerable AWS resources for
# demos and integration testing. Run with the admin profile.
# Usage: .\scripts\setup_test_lab.ps1

Write-Host "Creating test lab resources..."

# S3 - public bucket
aws s3api create-bucket --bucket cloudsentinel-lab-public-bucket --region us-east-1 --profile admin
aws s3api put-public-access-block --bucket cloudsentinel-lab-public-bucket --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false --profile admin
aws s3api put-bucket-ownership-controls --bucket cloudsentinel-lab-public-bucket --ownership-controls="Rules=[{ObjectOwnership=BucketOwnerPreferred}]" --profile admin
aws s3api put-bucket-acl --bucket cloudsentinel-lab-public-bucket --acl public-read --profile admin

# S3 - secure bucket for comparison
aws s3api create-bucket --bucket cloudsentinel-lab-secure-bucket --region us-east-1 --profile admin
aws s3api put-bucket-versioning --bucket cloudsentinel-lab-secure-bucket --versioning-configuration Status=Enabled --profile admin

# EC2 - vulnerable security group
$sg = aws ec2 create-security-group --group-name cloudsentinel-lab-open-sg --description "Lab: open SG" --profile admin | ConvertFrom-Json
$sgId = $sg.GroupId
aws ec2 authorize-security-group-ingress --group-id $sgId --protocol tcp --port 22 --cidr 0.0.0.0/0 --profile admin
aws ec2 authorize-security-group-ingress --group-id $sgId --protocol tcp --port 3389 --cidr 0.0.0.0/0 --profile admin

Write-Host "Test lab created."
Write-Host "  Public bucket: cloudsentinel-lab-public-bucket"
Write-Host "  Secure bucket: cloudsentinel-lab-secure-bucket"
Write-Host "  Open SG: $sgId"
Write-Host "Run scripts\teardown_test_lab.ps1 when done demoing."
