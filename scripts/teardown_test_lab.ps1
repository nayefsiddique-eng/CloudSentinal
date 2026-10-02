# Tears down the CloudSentinel test lab resources.
# Usage: .\scripts\teardown_test_lab.ps1

Write-Host "Tearing down test lab resources..."

aws s3api delete-bucket --bucket cloudsentinel-lab-public-bucket --profile admin
aws s3api delete-bucket --bucket cloudsentinel-lab-secure-bucket --profile admin

$sgs = aws ec2 describe-security-groups --filters "Name=group-name,Values=cloudsentinel-lab-open-sg" --profile admin | ConvertFrom-Json
foreach ($sg in $sgs.SecurityGroups) {
    aws ec2 delete-security-group --group-id $sg.GroupId --profile admin
}

Write-Host "Test lab removed."
