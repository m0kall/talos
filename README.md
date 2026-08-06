============ TALOS =============


A vm image scanner and recommender

This project includes a modified version of https://github.com/popey/sbom-vm

The code inside "tools/sbom-vm" directory is based on the original repository and has been modified to satisfy the requirements of Talos.

======== Basic Information ====================

Talos is a virtual image scanner that uses trivy,grype and osv-scanner to search and find vulnerabilities from a provided image.
Using a slightly modified version of sbom-vm (https://github.com/popey/sbom-vm) talos creates a Software Bill of Materials (SBOM) from an inputed image.
The sbom is saved at the "sboms" folder.After that it uses Trivy,Grype and lastly osv-scanner on the produced sbom to find vulnerabilities.
Each scanners result is saved seperatelly on the "scans" folder in a subfolder of each scanning tool. After all scanners have completed, talos merges the results
as a readable json on the "merged" folder. These results contain a sum up of the scans (total cves,risk score,epss score etc) and every vulnerability with its information.
Risk factor is calculated using the following function (and NOT CVSS v2 values):

( CVSS/10 ) X epss_percentile X 100.

The epss scores are calculated using the official API of FIRST.org : https://www.first.org/epss/api

Since a single image contains multiple CVES, when ranking the images based on their risk factor, the max value is used in order to determine which is safer than the other. In the case of 2 risk factors of 2 images are the same, a comparison is made on the next risk factor in order to determine which image is safer. This will continue until risk factors are different and the comparison can be made.

Results can be displayed on the cli filtered according to severity

You can also export the results as a .xlsx file that is saved on the "results" folder
Using the export function, it grabs all files saved at "merged" folder and combines them to 1 .xlsx file with 2 sheets.
First sheet is displaying all images ranked from safest to unsafest (ascending according their risk factor) and their general information (total found cves,highest cvss score,highest risk score,most dangerous cve)
Second sheet is displaying all found vulnerabilities with their info (what scanner found them,description,packages,fixed verion etc)

You can also use talos to scan public images on Amazon AWS and Google cloud services GCP (--online feature)
This requires some setup that is explained on the bellow chapters
All credentials are handled by AWS and GCP libraries or env vars and are not read by talos.

While using --online feature, talos can either scan 1 image (AMI or GCP) or you can provide a txt file containing either a "shortform input" or a full path to the image:
This means either:

*For AWS:

aws/ami-AMIID 

or 

ARN: arn:aws:ec2:<region>:<account>:image/<ami-id>

*For GCP:

gcp/image

or 

gcp/projects/<owner-project>/global/images/<image-name>

This txt file can contain both amis and gcp images and talos will connect and scan to each provider accordingly.You do need to provide the information needed for each provider (bucket name,project name (gcp-only),region(aws),zone(gcp)) for this command to run properly.
For more information and examples you can see the last steps of the online first time setups on the below chapters and on the all commands chapter.

The overall logic of the online feature goes as follows:
*talos creates an instance on worker (curently supports only aws and gcp)
*installs itself there
*scans the provided image
*saves and uploads the result on a bucket
*downloads the json file from that bucket to the "merged" folder
*Terminates all resources instance,disks,json file on the bucket. Keep in mind it does not delete the bucket and it is a prerequisite that you already created one yourself.

You can use talos --help for information on each command and how to use them. Also on the chapters bellow are a few examples and explanations

========== Installation ==========

You can install talos to your cli by using this commands:

git clone https://github.com/m0kall/talos.git
cd talos
chmod +x install.sh
./install.sh

this will copy the current repository,cd in the folder, make the installation file executable and run it
the install.sh contains every library for this project to work on your system including the scanners.

you can just run this using python3 but it is suggested to install it in case you run into some libraries missing like google cloud compute etc

===== Local Scanning ========

Talos can either scan 1 local image or you can provide it with a txt file containing the paths multiple .img files.
Firstly, talos will create an SBOM from the .img file and save it to the "sboms" folder.
After that the scanning will begin using Trivy,Grype and lastly OSV-scanner. Each seperate scanner will save its results to its specified subfolder located in "scans" folder
When scanning is finished, talos will merge each scanner's result to 1 merged json file saved on the "merged" folder. This file contains all the information about the scanned image. 
You can then display the results filtered by severity on the cli or you can export them. The export function looks on the "merged" folder and combines all the jsons there into 1 
.xlsx file saved on the "results" folder 

Some command examples include:

*this scans the image on the given path
talos scan --image path/to/image.img

*this scans all the images located on the txt file that contains their paths
talos scan --file images_file_name.txt

Note:the txt should be writting following this structure:
/home/user/images/image.img

*this displays info of the scans on the cli (by default limited to 50 for visibility and only critical/high severity)
talos display --image merged/image-merged.json

*same as above but shows 100 entries with any severity (ranked by risk factor)
talos display --image merged/image-merged.json --severity all --limit 100

*displays every previously scanned image (located in the merged folder) ranked from safest to riskiest
talos display --all

=========== Talos All Available Commands =============

Here are all the commands you can use and a quick explenation of them:

*scan a single local .img file
talos scan --image <path>

*scan multiple local images their path listed on specified txt file
talos scan --file <path>

*displays vuln info on given image
talos display --image <path to merged json>
    --limit <n>                                   max rows to display (default is 50)
    --severity <all|critical|high|medium|low>     Filter rows by severity (default shows critical/high)

*this displays all images found in merged folder ranked from safest to riskiest.info includes (total cves,max cvss,max risk factor,riskiest cve)
talos display --all

*this combines all results saved into merged folder into 1 .xlsx file with 2 sheets containing all info(saved in results folder)
talos export

*Scan a single AWS image. Identifier can either be aws/ami-xxxx or an ARN like: aws/arn:aws:ec2:<region>:<account>:image/<ami-id>
talos scan --online --image <identifier> --awsbucket <name> [--region <region> if you want different than default (us-east-1)] [--profile <name>] 
note: by following the setup instuctions bellow the default profile name is talos-ssm-profile.You can change the name if you want

*scan a single gcp image. <identifier> can either be gcp/image-name (located inside your project) or a full path like: gcp/projects/<owner-project>/global/images/<name>
talos scan --online --image <identifier> --gcpbucket <name> --project <id> [--zone <zone> (default is us-east1-b)]  [--serviceacc <email> if not provided fallsback to env var]

*same as the above commands.in this case talos scans every image on the provided txt file on any provider (currently supports AWS and GCP)
*the local txt file contains paths examples as above either short form or full paths (aws/image or gcp/image or arn or full gcp path)
*you need to provide all the information for each provider like bucket names project etc.
talos scan --online --file <path> --awsbucket <name> --gcpbucket <name> --project <id> [--region ...] [--zone ...]

*show help message
talos -h / talos <command> -h

=================== Provider Setup Instructions =============================

============= AWS First time setup instructions ============

In order for talos to connect to your AWS account and scan specified ami images, you need to properly setup the following:
1) create an IAM User with policies AmazonEC2FullAccess, AmazonS3FullAccess, AmazonSSMFullAccess, IAMFullAccess. You can use the website to attach these policies
2) Create access keys
3) since talos does not store or ask for credentials keys direcly and uses boto3 it automatically looks for enviromental variables.
   You can either run this on your console:
   
   export AWS_ACCESS_KEY_ID="your-access-key-id"
   export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
   
   or use "aws configure" if you have already installed  AWS CLI (next steps require aws cli).

4) The worker instance that runs talos needs its own permissions. These are SSM and S3 access.
  you can grant these permissions by pasting the following text.This creates an IAM role trusted by EC2 and grants it SSM access in order for talos to control the worker instance:


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

 
      aws s3 mb s3://your-bucket-name --region your-region

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

   
6) After this you are ready to run a scan by using --online argument on the AWS provider.Some examples include:
  talos scan --online --image aws/ami-XXXX --awsbucket your-bucket-name
  talos scan --online --image aws/arn:aws:ec2:<region>:<account>:image/<ami-id> --awsbucket your-bucket-name
  talos scan --online --file cloudimages.txt --awsbucket your-bucket-name

if you do not pass an argument on --region talos default region is us-east-1

you can always use talos --help for more information



============== GCP First Time Setup Instructions =============

In order for talos to connect to your AWS account and scan specified gcp images, you need to properly setup the following:

1) Run the install.sh script to your local machine OR just download google cloud compute and paramiko using:
pip3 install google-cloud-compute google-cloud-storage paramiko --break-system-packages

2) Create a GCP project (or use an existing one) that is connected to a billing account

3) Enable the required APIS for the project using:
gcloud services enable compute.googleapis.com storage.googleapis.com --project=YOUR_PROJECT_ID

4) Create a service account that Talos will use to orchestrate resources and run the workers instance identity using the following command:

gcloud iam service-accounts create talos-cli --project=YOUR_PROJECT_ID

5) Grant the service account the permissions compute admin and storage admin. you can use the following commands:

   gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
     --member="serviceAccount:talos-cli@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/compute.admin"

    gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:talos-cli@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/storage.objectAdmin"   

  After that add the permission for the service account to launch a vm running as itself. On that worker instance the scanning phase will take place.
  You can use the following commands:

     gcloud iam service-accounts add-iam-policy-binding talos-cli@YOUR_PROJECT_ID.iam.gserviceaccount.com \
     --member="serviceAccount:talos-cli@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/iam.serviceAccountUser" \
     --project=YOUR_PROJECT_ID

6) Download a key file for the service account and point GOOGLE_APPLICATION_CREDENTIALS at it. This is used for authentication
note that talos does not read your credentials.It is fully handled by google
   
   gcloud iam service-accounts keys create talos-cli-key.json \
     --iam-account=talos-cli@YOUR_PROJECT_ID.iam.gserviceaccount.com

    then use:
    export GOOGLE_APPLICATION_CREDENTIALS="/path/to/talos-cli-key.json"

7) Set the service account email as an enviroment variable.

    You can either use this:
     export TALOS_GCP_SERVICE_ACCOUNT="talos-cli@YOUR_PROJECT_ID.iam.gserviceaccount.com"
    
    Or pass it on each run using --serviceacc argument

    For simplicity,you can add both exports (steps 6-7) to your ~/.bashrc in order for them to persist across terminal sessions. This is optional though

8) Create a Cloud Storage bucket to download scan results into using the following:

  gsutil mb -p YOUR_PROJECT_ID gs://your-bucket-name

9) After this you are ready to run a scan by using --online argument on the GCP provider.

by using a form like: gcp/image-name talos looks for the image inside the project you pass with --project.This is used for images already copied to your own personal project

by using a full path form like: gcp/projects/<owner-project>/global/images/<image-name> talos looks up the image on that path and runs itself 
inside your own project thats passed in the --project argument 

some example commands include:

    (this commands requires you to copy the image inside your personal project)
    talos scan --online --image gcp/gcp-image-name --gcpbucket your-bucket-name --project YOUR_PROJECT_ID --zone your-zone
    
    (this is a command using the full path to an image)
    talos scan --online --image gcp/projects/<family project>/global/images/<image name> --gcpbucket your-bucket-name --project YOUR_PROJECT_ID --zone your-zone

    talos scan --online --file cloudimages.txt --gcpbucket your-bucket-name --project YOUR_PROJECT_ID --zone your-zone

    --file argument can scan batches of both amis and gcp images. all that is required is you providing the buckets projects etc arguments for each provider
    --zone argument if not specified will always default to us-east1-b

    you can always use talos --help for more information

==========================================================================


======= Miscellaneous ============

This project was developed as a part of a bachelor's thesis at the University of the Aegean
You are welcome to use this project, build upon it and experiment with it as you see fit.
May this project proves useful to others and help you learn, as it helped me.
Take care!
