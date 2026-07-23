==TALOS_==


A vm image scanner and recommender

This project includes a modified version of https://github.com/popey/sbom-vm

The code inside "tools/sbom-vm" directory is based on the original repository and has been modified to satisfy the requirements of Talos.


================================================ AWS First time setup instructions========================================================
In order for talos to connect to your AWS account and scan specified ami images, you need to properly setup the following:
1) create an IAM User with policies AmazonEC2FullAccess, AmazonS3FullAccess, AmazonSSMFullAccess
2) Create access keys
3) since talos does not store or ask for credentials keys direcly and uses boto3 it automatically looks for enviromental variables.
   You can either run this on your console:
   
   export AWS_ACCESS_KEY_ID="your-access-key-id"
   export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
   
   or use "aws configure" if you have already installed  AWS CLI (steps 4-5 require aws cli).
4) The worker instance that runs talos needs its own permissions. These are SSM and S3 access.
  you can grand these permissions by pasting the following text.This creates an IAM role trusted by EC2 and grants it SSM access in order for talos to control the worker instance:
   cat > /tmp/ec2-trust-policy.json << 'EOF'
   {
     "Version": "2012-10-17",
     "Statement":[{
   
       "Effect": "Allow",
       "Principal": {"Service": "ec2.amazonaws.com"},
       "Action": "sts:AssumeRole"
   
     }]
   }
   EOF

   aws iam create-role --role-name talos-ssm-role --assume-role-policy-document file:///tmp/ec2-trust-policy.json
   aws iam attach-role-policy --role-name talos-ssm-role --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
   aws iam create-instance-profile --instance-profile-name talos-ssm-profile
   aws iam add-role-to-instance-profile --instance-profile-name talos-ssm-profile --role-name talos-ssm-role

5) You need to create an S3 Bucket in order to download the scan results to your local machine and attach an upload policy to it. you can do that by pasting the following text. This creates a bucket and grants the role permission to upload results into it
      aws s3 mb s3://your-bucket-name --region us-east-1

   cat > /tmp/s3-upload-policy.json << EOF
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["s3:PutObject"],
       "Resource": ["arn:aws:s3:::your-bucket-name/*"]
     }]
   }
   EOF

   aws iam put-role-policy --role-name talos-ssm-role --policy-name talos-s3-upload --policy-document file:///tmp/s3-upload-policy.json
6) After this you are ready to run a scan by using --online argument.Some examples include:
  talos scan --online --image aws/ami-XXXX --bucket your-bucket-name
  talos scan --online --file cloudimages.txt --bucket your-bucket-name
you can always use talos --help for more information
