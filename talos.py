#!/usr/bin/env python3
import argparse
import subprocess
import os
from pathlib import Path
import json
import sys
import urllib.request
from tabulate import tabulate
import openpyxl
from datetime import datetime
import boto3
import time
import paramiko
import re
from google.cloud import compute_v1
from google.cloud import storage 


#Based on numerous test, with these constants it is guranteed that there will be enough ram & disk space for talos to work on an AWS instance within a reasonable time
#scan per image should take around 5minutes (depending on target ami & its vulnerabilities) while installation around 10
#You can always use your prefered values at your own risk.
INSTANCE_TYPE="t3.small"
ROOT_DISK= 20
#SWAP_SIZE= 2

#these are the constants for the GCP machine.again you can always use your prefered settings by just changing these
#with these settings scan per image is completed within around 15minutes (depenting on target img & its vulrenabilities)
GCP_INSTANCE_TYPE="e2-medium"
GCP_ROOT_DISK=20
GCP_DISK_TYPE="pd-balanced"
GCP_IMAGE_FAMILY="ubuntu-2404-lts-amd64" #this is the instance running os.
GCP_IMAGE_PROJECT="ubuntu-os-cloud" #gcp owner of the image family


##anchoring path to script directory
BASE_DIR= Path(__file__).resolve().parent


#compare 2 severities
def higher_severity(string1,string2):

    #using each entries index (0-5) to "convert" the strings to numbers then return the bigger number/severity
    severity_order= ["UNKNOWN","NONE","LOW","MEDIUM","HIGH","CRITICAL"] 

    if string1 in severity_order:
        num1= severity_order.index(string1)
    else: 
        num1= 0 #just in case if severity is not inside the severity_order array we treat it as an unknown   
  
    if string2 in severity_order:    
        num2= severity_order.index(string2)
    else:
        num2= 0

    if num1 >= num2:
          return string1
    else: return string2



#osv returns a number instead of a label (low,medium etc)
def osv_cvss_score2severity(score):
    
    try:
        score=float(score) #osv returns a string
    except (TypeError, ValueError):
        return "UNKNOWN" #osv did not have a value on some CVSS scores in testing so we return "UNKNOWN" in those entries note that these uknown get handled at merge logic
    
    #using the official CVSS v3 Standard
    if     score == 0.0:   return "NONE"
    elif   score <  4.0:   return "LOW"
    elif   score <  7.0:   return "MEDIUM"
    elif   score <  9.0:   return "HIGH"
    else:                  return "CRITICAL"

#grype stores cvss in lists of dictionaries we parse the whole list and grab the highest score
def grype_compare_cvss_from_list(cvss_list):

    big = None

    for entry in cvss_list:

        score= entry.get("metrics", {}).get("baseScore")

        if score is not None:

            if big is None or score>big:

                big=score

    return big

#trivy stores cvss in dictionary of dictionaries 1per source
def trivy_compare_cvss_from_dict(cvss_dict):

    big = None

    #get cvss score
    for data in cvss_dict.values():
        score= data.get("V3Score")

        if score is not None:
            if big is None or score>big:
                big=score    

    return big

#parse trivy results and save them to a standard structure (dictionary)
def trivy_parse(path):

    with open(path, encoding="utf-8") as f:
        
        data= json.load(f)
    
    results= {}
    skipped= 0
    
    #parsing trivy results according to trivy's structure. #DELETEME explain in pdf the structure of trivys data
    #if no results where found we get an empty list []
    for target in data.get("Results",[]):
        for vulnerabilities in (target.get("Vulnerabilities") or []):

            vulnid= vulnerabilities.get("VulnerabilityID","")
            
            #skipping and counting all non CVE vendor IDs
            if not vulnid.startswith("CVE-"):
                skipped+=1
                continue

            cvss_raw= vulnerabilities.get("CVSS") or {} #if cvss missing returns empty dictionary {}

            #DELETE ME AND WRITE IN PDF using a dict of dicts for faster search. merger can find cvid instantly and not go through the whole data
            
            #our standrard structure:
            results[vulnid]= {

                "id":                           vulnid,
                "severity":                     vulnerabilities.get("Severity", "UNKNOWN").upper(), #if missing return UNKNOWN
                "cvss_score":                   trivy_compare_cvss_from_dict(cvss_raw), #get the highest cvss from comparing all ventors scores
                "description":                  vulnerabilities.get("Description", ""),

                "package": { 

                    "name":                     vulnerabilities.get("PkgName"),
                    "version":                  vulnerabilities.get("InstalledVersion")

                },                              
                                                
                "fixed_version":                vulnerabilities.get("FixedVersion"),
                "references":                   vulnerabilities.get("References",[]),
                "found_by":                     ["trivy"]
            }

    if skipped>0:
        print(f"[!] Trivy skipped {skipped} non-CVE advisories")
    
    #returns a tuple so we can save skipped later to the merger
    return results, skipped

#same logic as trivy parse and save to our structure
def grype_parse(path):

    with open(path, encoding="utf-8") as f:
        data= json.load(f)

    results= {}
    skipped= 0

    #parsing grype results according to grype structure same logic as trivy
    for matches in data.get("matches", []):

        #DELETEME explain this to the pdf (grype structure)
        vuln= matches.get("vulnerability", {})
        arti= matches.get("artifact", {})
        vulnid= vuln.get("id","")

        #skipping non cve vendors
        if not vulnid.startswith("CVE-"):
            skipped+=1
            continue
        
        #standard structure
        results[vulnid]={
            "id":                   vulnid,
            "severity":             vuln.get("severity", "UNKNOWN").upper(),
            "cvss_score":           grype_compare_cvss_from_list(vuln.get("cvss",[])),
            "description":          vuln.get("description",""),
            
            "package":{

                    "name":         arti.get("name"),
                    "version":      arti.get("version"),
                    "purl":         arti.get("purl"),
                    "type":         arti.get("type")
            },

            "fixed_version":        vuln.get("fix",{}).get("versions",[]),
            "references":           vuln.get("urls",[]),
            "found_by":             ["grype"]
        }

    if skipped>0:
        print(f"[!] Grype skipped {skipped} non-CVE advisories")

    return results,skipped

#same as the other scanners above
def osv_parse(path):

    with open(path,encoding="utf-8")as f:
        data= json.load(f)

    res= {}
    skipped = 0


    for results in data.get("results", []):
        for package in results.get("packages", []):

            package_info= package.get("package",{})

            #cve id in osv is stored in aliases list
            for groups in package.get("groups", []):
                cveid= None
                for alias in groups.get("aliases",[]):
                    #grab first seen cve
                    if alias.startswith("CVE-"):
                        cveid= alias
                        break
                #counting non CVE ids
                if not cveid:
                    skipped+=1
                    continue


                raw_score= groups.get("max_severity")
                if raw_score:
                    cvss_score= float(raw_score)
                else:
                    cvss_score= None
                
                res[cveid]={

                    "id":                   cveid,
                    "severity":             osv_cvss_score2severity(raw_score),
                    "cvss_score":           cvss_score,
                    "description":          "", #osv doesnt provide description

                    "package": {

                        "name":             package_info.get("name"),
                        "version":          package_info.get("version")

                    },
                    "fixed_version":        None, #osv doesnt provide 
                    "references":           [],   #osv doesnt provide
                    "found_by":             ["osv"]
                }

    if skipped>0:
        print(f"[!] OSV skipped {skipped} non-CVE advisories")

    return res, skipped

def merger(trivy,grype,osv):

    merged= {}

    #this gets all unique cve ids from each scanner
    all_cve= set(trivy) | set(grype) | set (osv)

    #create an empty dict (default values) with each cve id
    for cve_id in all_cve:
        
        combination={
            "id":               cve_id,
            "severity":         "UNKNOWN",
            "cvss_score":       None,
            "description":      "",
            "package":          {},
            "fixed_version":    None,
            "references":       [],
            "found_by":         []
        } 

        #loop through all the data
        for source, source_data in [("trivy",trivy),("grype",grype),("osv",osv)]:

            #if scanner has not this cve id we skip the entry
            if cve_id not in source_data:
                continue

            entry= source_data[cve_id]
            combination["found_by"].append(source)
            
            #get highest secerity and cvss score for the current cve from all the scanners
            combination["severity"]= higher_severity(combination["severity"],entry["severity"])

            if entry.get("cvss_score") is not None:
                if combination["cvss_score"] is None or entry.get("cvss_score")> combination["cvss_score"]:
                    combination["cvss_score"]= entry.get("cvss_score")
            
            #set description etc if empty (we only save the first we get higherhy goes like: Trivy > Grype > OSV)
            if not combination["description"] and entry.get("description"):
                combination["description"]= entry.get("description")

            if not combination["package"] and entry.get("package"):
                combination["package"]= entry.get("package")

            if not combination["fixed_version"] and entry.get("fixed_version"):
                combination["fixed_version"]= entry.get("fixed_version")                

            #get the references from all scanners not only the first we see
            for references in entry.get("references",[]):

                if references not in combination["references"]:

                    combination["references"].append(references)

        merged[cve_id]= combination

    return merged

#calculating risk factor by calling FIRST api and fetching epss scores
def epss_calc(merged):

    print("Fetching EPSS scores from FIRST.org")

    #get CVE names
    cveids= list(merged.keys())
    batch_size=100 #send to the api multiple batches of 100 cves. this number has been tested for ~8k results but if needed you can change this number without breaking the function
    api_results={}



    for i in range (0,len(cveids),batch_size):

        batch= cveids[i:i+batch_size]
        #api url + our cves
        url=f"https://api.first.org/data/v1/epss?cve={','.join(batch)}"

        try:
            #send batch to api (identifying as talos maybe get past some block errors)
            req= urllib.request.Request(url, headers={"User-Agent": "Talos"})
            
            #if response takes >10seconds we skip the entry
            with urllib.request.urlopen(req, timeout=10) as response:
                res= json.loads(response.read().decode())
            
            #save responce to api_results
            for entry in res.get("data",[]):
                
                api_results[entry["cve"]]={
                    "epss_score":               float(entry["epss"]),
                    "epss_percentile":          float(entry["percentile"])
                }
        
        except Exception as e:
            
            print(f"[!] Failed to fetch EPSS score for batch {i//batch_size} skipping...: {e}")
            continue


    #save epps and risk factor calc to dict
    #cve_id is the key to the merged dict. cve_info is the direct merged info (severity,cvss score etc)
    #we directly edit the merged info from the merger function and we add the new information of epss scores
    zero_epss=0

    for cve_id, cve_info in merged.items():
        
        epss_numbers= api_results.get(cve_id)

        if epss_numbers:
            cve_info["epss_score"]=             epss_numbers["epss_score"]
            cve_info["epss_percentile"]=        epss_numbers["epss_percentile"]

            if cve_info.get("cvss_score") is not None:
                #calculate risk factor according to formula, and rounding to 4 digits
                cve_info["risk_factor"]= round((cve_info["cvss_score"]/10)* cve_info["epss_percentile"]*100,4)
            else:
                cve_info["risk_factor"]= None

        else:
            #print("[!] This cve cannot be found on FIRST database")
            cve_info["epss_score"]=None
            cve_info["epss_percentile"]=None
            cve_info["risk_factor"]=None
            zero_epss+=1            

    print(f"[+] Successfully fetched EPSS scores for {len(api_results)} CVEs")
    if zero_epss>0:
        print(f"[!] {zero_epss} CVEs had no EPSS data available")

    return merged


def save_merged(scan_path,image_name,out_path):

    print("[+] Merging scan results...")

    #parsers return tuple so needs unpacking
    trivy, trivy_skipped=    trivy_parse(scan_path["trivy"])
    grype, grype_skipped=    grype_parse(scan_path["grype"])
    osv, osv_skipped    =    osv_parse(scan_path["osv"])

    if not trivy:
        print("[-] Trivy produced no results!")
    if not grype:
        print("[-] Grype produced no results!")
    if not osv:
        print("[-] OSV-Scanner produced no results!")

    #merge scanner input
    merged= merger(trivy,grype,osv)

    print(f"[+]Trivy found {len(trivy)} Vulnerabilities")
    print(f"[+]Grype found {len(grype)} Vulnerabilities")
    print(f"[+]OSV found {len(osv)} Vulnerabilities")

    if not merged:
        print("[!] No CVEs found after merging. Skipping saving results...")
        return None 
    
    #add epss score to the merged results using api call (FIRST.org)
    merged= epss_calc(merged)

    #build path
    merged_dir= Path(out_path)/"merged"
    merged_dir.mkdir(exist_ok=True)
    out_file= merged_dir/ f"{image_name}-merged.json"

    #counting cves found by more than 1 scanner
    i=0  
    for ids in merged.values():
        if len(ids["found_by"])>1:
            i+=1

    max_risk_factor           = None
    max_risk_cve              = None
    max_cvss                  = None
    max_cvss_cve              = None
    max_epss_score            = None
    max_epss_score_cve        = None
    max_epss_percentile       = None
    max_epss_percentile_cve   = None

    #get max risk factor etc and savethem 
    for cve_id, cve_data in merged.items():
        
        if cve_data.get("risk_factor") is not None:
            if max_risk_factor is None or cve_data["risk_factor"]> max_risk_factor:
                max_risk_factor= cve_data["risk_factor"]
                max_risk_cve= cve_id
        
        if cve_data.get("cvss_score") is not None:
            if max_cvss is None or cve_data["cvss_score"]> max_cvss:
                max_cvss= cve_data["cvss_score"]
                max_cvss_cve= cve_id

        if cve_data.get("epss_score") is not None:
            if max_epss_score is None or cve_data["epss_score"]> max_epss_score:
                max_epss_score= cve_data["epss_score"]
                max_epss_score_cve= cve_id

        if cve_data.get("epss_percentile") is not None:
            if max_epss_percentile is None or cve_data["epss_percentile"]> max_epss_percentile:
                max_epss_percentile= cve_data["epss_percentile"]
                max_epss_percentile_cve= cve_id                        



    output= {
        "stats":{
            "total_cves":                    len(merged),
            "trivy_cves":                           len(trivy),
            "grype_cves":                           len(grype),
            "osv_cves":                             len(osv),
            "cves_foundby_multiple_scanners":       i,
            "trivy_non_cve_vendors":                trivy_skipped,
            "grype_non_cve_vendors":                grype_skipped,
            "osv_non_cve_vendors":                  osv_skipped,
            "max_risk_factor":                      max_risk_factor,
            "max_risk_factor_cve":                  max_risk_cve,
            "max_cvss":                             max_cvss,
            "max_cvss_cve":                         max_cvss_cve,
            "max_epss_score":                       max_epss_score,
            "max_epss_score_cve":                   max_epss_score_cve,
            "max_epss_percentile":                  max_epss_percentile,
            "max_epss_percentile_cve":              max_epss_percentile_cve,
        },
        "found_vulnerabilities":                    merged
    }

    #save files
    try:
        with open(out_file,"w",encoding="utf-8") as f:
            json.dump(output,f,indent=2)

        print(f"[+] Merged results from all scanners saved at:  {out_file}")
    except Exception as e:
        print(f"[-] Critical error while saving merged results:{e}. Please check permissions or free space")
        return None

    return str(out_file)

def generate_sbom(image_path):
    print(f"[+] Generating SBOM from image: {image_path}")

    #image_path = str(image_path)

    #ensure target folder exists
    (BASE_DIR / "sboms").mkdir(exist_ok=True)
    (BASE_DIR / "logs/sbomLogs").mkdir(parents=True , exist_ok=True)

    #Path("sboms").mkdir(exist_ok=True)
    #Path("logs/sbomLogs").mkdir(parents=True, exist_ok=True)

    #catch img name
    #imagename = Path(image_path).stem

    #run sbom script (needs sudo)
    try:
        subprocess.run(
            ["python3",str(BASE_DIR/ "tools"/"sbom-vm"/"sbom-vm.py"),str(image_path),str(BASE_DIR)],check=True
                #"python3","tools/sbom-vm/sbom-vm.py",str(image_path)], check=True

        )

        #list of all sbom.json created files both .json
        sbomfiles = list((BASE_DIR).glob("*_sbom_*.json"))
        logfiles = list((BASE_DIR).glob("*.log"))
        #sbomfiles =list(Path(".").glob("*_sbom_*.json"))
        #logfiles =list(Path(".").glob("*.log")) #same for logfiles

        if not sbomfiles:
            print("[-] Failed to find any generated SBOM")
            return None
        
        if logfiles:
            newlog = max(logfiles, key=os.path.getctime)
            logfile = BASE_DIR / "logs/sbomLogs" / f"{newlog.stem}.log"
            #logfile = Path("logs/sbomLogs") / f"{imagename}.log"
            newlog.rename(logfile)
        else:
            print("[!] Failed to find logfile")
            
        #catch newest file (incase there are other files in folder)
        newsbom = max(sbomfiles, key=os.path.getctime)
        

        #move to correct folder
        sbom = BASE_DIR / "sboms" / f"{newsbom.stem}.cdx.json"
        #sbom = Path("sboms") / f"{imagename}.cdx.json"
        newsbom.rename(sbom)



    except Exception as e :
        print(f"[-] SBOM Generation Failed: {e}")
        return None

    if sbom.exists():
        print(f"[+] SBOM Generated with name: {sbom}")
        return str(sbom)
    else:
        print("[-] Unable to save sbom ")
        return None

#this is used on aws/gcp enviroment
def generate_sbom_from_mounted_path(mount_path,image_name,output):

    print(f"[+] Generating SBOM from mounted path:{mount_path}")

    (Path(output)/"sboms").mkdir(exist_ok=True)
    
    sbom=Path(output)/"sboms"/f"{image_name}.cdx.json"

    try:
        #using syft on mounted path for the image provided by aws/gcp
        subprocess.run(
            ["syft","--override-default-catalogers","image",str(mount_path),"-o",f"cyclonedx-json={sbom}"],check=True
        )

    except Exception as e:
        print(f"[-] SBOM Generation failed: {e}")
        return None
        
    if sbom.exists():
        print(f"[+] SBOM generated with name:{sbom}")
        return str(sbom)
    
    
    else:
        print("[-] Critical error: failed to save SBOM")
        return None

#look snapshot for given AMI (user input) to create the volume needed in order to scan it
def aws_get_snapshot_id(ec2_client,ami_id):
    
    #get information about users given ami
    response= ec2_client.describe_images(ImageIds=[ami_id])

    #save aws response info inside a list
    images= response.get("Images",[])

    if not images:
        print(f"[-] AMI with name {ami_id} not found")
        return None
    
    #look for all disks and get the root disk
    #the root disk is the disk that we actually need to scan (contains all the info our scanners want)
    for device in images[0].get("BlockDeviceMappings",[]):
        if "Ebs" in device:
            #return the snapshot of the root disk
            return device["Ebs"]["SnapshotId"]
    
    print(f"[-] No snapshot found for AMI {ami_id}")        
    return None

#in testing there were some problems on installation of talos when using some specific amis
#with this function we always use a specific one that the pipeline worked correctly
#ubuntu 24.04 AMI, always succeded in installing talos correctly
#this has nothing to do with the users input of ami that needs to be scanned, this affects the instance running os
#if for any reason you want to use a different ami you can change this information but it is not recommended
def aws_get_worker_ami(ec2_client):

    response= ec2_client.describe_images(

        #this amis owned by a specific account
        #it grabs  the official company that makes ubuntu (Canonical) so we get an official ubuntu image not a random one
        Owners=["099720109477"],
        
        #these filters find only available amis with the exact naming pattern of official ubuntu 24.04 (Noble) amis
        Filters=[

            {"Name":"name","Values":["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]},
            {"Name":"state","Values":["available"]}
        ]
    )
    #get all images that mach above filters etc
    images=response.get("Images",[])

    if not images:
        print(f"[-] Could not find a worker AMI")
        return None
    
    #find the newest image/latest version by comparing creation dates of amis
    newest_ami=None
    newest_date=""

    for image in images:

        current_date=image["CreationDate"]

        if current_date>newest_date:
            newest_date=current_date
            newest_ami=image
            
    if newest_ami:
        return newest_ami["ImageId"]
    
    else:
        print("[-] Critical error: failed lookup for newest version of worker AMI")
        return None

#launch instance/ami on worker where the scanning will ocure
def aws_launch_worker(ec2_client,instance_profile,availability_zone):
    
    #get latest version
    worker_ami=aws_get_worker_ami(ec2_client)
    
    if not worker_ami:
        print("[-] Critical error while fetching worker ami")
        return
    
    #run the instance using our default configurations (constants at lines 20-22)
    response=ec2_client.run_instances(
        ImageId=worker_ami,
        InstanceType= INSTANCE_TYPE,
        IamInstanceProfile={"Name":instance_profile}, #this has the permissions. user need to set them up for talos to work correctly. See readme on github about these permissions
        Placement={"AvailabilityZone":availability_zone},
        BlockDeviceMappings=[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":ROOT_DISK}}],
        MinCount=1,
        MaxCount=1
    )
    #this returns the instance id. basically it works like: get list of instances,get the 1st instance on it,get id
    return response["Instances"][0]["InstanceId"]

#wait untile worker is ready to recieve commands through ssm
def aws_wait_for_ssm(ssm_client,instance_id,timeout=120):
    print("[!] Waiting for worker instance to register with SSM")
    wait=0

    while wait<timeout:
        response=ssm_client.describe_instance_information(

            Filters=[{"Key":"InstanceIds","Values":[instance_id]}]
        )
        if response["InstanceInformationList"]:
            print("[+] Worker instance is online successfully")
            return True
        time.sleep(5)
        wait+=5

    print("[-] Timed out waiting for SSM. Worker instance offline")
    return False

#send and run shell commands to worker and wait for them to finish. max wait time is set to 10 minutes.in testing results needed max 5minutes
#this function returns 3 things: if command succeded, command output and error message if any
def aws_run_command(ssm_client,instance_id,commands,timeout=600):

    response=ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands":commands}
    )
    #save command unique id to check on its progress
    command_id=response["Command"]["CommandId"]

    #wait for command to run
    wait=0
    while wait<timeout:
        time.sleep(5)
        wait+=5
        try:
            result=ssm_client.get_command_invocation(CommandId=command_id,InstanceId=instance_id) #check on command status
        except ssm_client.exceptions.InvocationDoesNotExist:
            continue #ssm sometimes needs more time
        
        #stop when command finishes
        if result["Status"]in ("Success","Failed","Cancelled","TimedOut"):
            return result["Status"]=="Success",result.get("StandardOutputContent",""),result.get("StandardErrorContent","")
             
    return False,"","Timed out while waiting for command to run"

def aws_create_and_attach_volume(ec2_client,snapshot_id,instance_id,availability_zone):
    #create volume from snapshot
    volume=ec2_client.create_volume(SnapshotId=snapshot_id,AvailabilityZone=availability_zone)
    #save volume unique id
    volume_id=volume["VolumeId"]
    
    #wait for volume to be ready
    ec2_client.get_waiter("volume_available").wait(VolumeIds=[volume_id])
    
    #attach volume to worker
    ec2_client.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")

    #wait again until volume is ready
    ec2_client.get_waiter("volume_in_use").wait(VolumeIds=[volume_id])

    #used to terminate volume on the end of the programm
    return volume_id

def aws_cleanup(ec2_client,instance_id,volume_id):
    print("[!] Terminating AWS resources...")

    if instance_id:

        try:
            ec2_client.terminate_instances(InstanceIds=[instance_id])

            #wait until instance is successfully terminated
            ec2_client.get_waiter("instance_terminated").wait(InstanceIds=[instance_id])
            print(f"[+] Instance {instance_id} successfully terminated!")

        except Exception as e:
            print(f"[-] Could not terminate instance {instance_id}: {e}. Please terminate manually")
    if volume_id:

        try:
            time.sleep(5) #wait a few extra seconds for safety
            ec2_client.delete_volume(VolumeId=volume_id)
            print(f"[+] Volume {volume_id} successfully terminated!")

        except Exception as e:

            print(f"[!] Could not delete volume {volume_id}: {e}.Please try manual termination of both instance and volume!")

    print("[+] Cleanup completed successfully")

    return

#get the gcp image info the user wants scanned
def gcp_get_source_image(images_client,project_id,image_name):
    try:
        image=images_client.get(project=project_id,image=image_name)
        return image.self_link

    except Exception as e:
        print(f"[-] gcp image {image_name} not found: {e}")
        return None

#ssh key for google (needed for client-master communication)
def gcp_generate_keypair():

    key=paramiko.RSAKey.generate(2048)
    #according to gcp standad metadata format this will authenticate us and create a vm username "talos" and connect it with a key
    public_key_str=f"talos:{key.get_name()} {key.get_base64()} talos"

    return key,public_key_str

#gcp launch worker,boot disk and ssh bind
def gcp_launch_worker(instances_client,project_id,zone,instance_name,service_account_email,public_key_str):

    #gcp-specific path for our instance type (e2-medium is default) 
    machine_type=f"zones/{zone}/machineTypes/{GCP_INSTANCE_TYPE}"

    #instance info
    instance=compute_v1.Instance(
        name=instance_name,
        machine_type=machine_type,#left variable is what compute_v1.Instance expects, right is our local variable

        #boot disk for the running instance
        disks=[
            compute_v1.AttachedDisk(

                #disk will delete automatically when instances is deleted
                #no need to write this in termination function
                #note this is the BOOT disk not the disk that holds target gcp img
                auto_delete=True,
                boot=True,

                initialize_params=compute_v1.AttachedDiskInitializeParams(

                    source_image=f"projects/{GCP_IMAGE_PROJECT}/global/images/family/{GCP_IMAGE_FAMILY}", #
                    disk_size_gb=GCP_ROOT_DISK,
                    disk_type=f"zones/{zone}/diskTypes/{GCP_DISK_TYPE}",
                )
            )
        ],

        #create an external ip to communicate with machine (using ssh)
        network_interfaces=[
            compute_v1.NetworkInterface(
                access_configs=[compute_v1.AccessConfig(name="External NAT", type_="ONE_TO_ONE_NAT")]
            )
        ],

        #extra needed permissions (used for results upload) 
        service_accounts=[
            compute_v1.ServiceAccount(email=service_account_email, scopes=["https://www.googleapis.com/auth/cloud-platform"])
        ],

        #store ssh key on vm for communication
        metadata=compute_v1.Metadata(
            items=[compute_v1.Items(key="ssh-keys", value=public_key_str)]
        ),
    )

    #create instance opperation (with the settings above)
    op=instances_client.insert(

        project=project_id,
        zone=zone,
        instance_resource=instance

    )
    #wait for instance setup completion
    op.result()
    return instance_name

def gcp_create_attach_disk(disks_client,instances_client,project_id,zone,image_self_link,instance_name,disk_name):

    #create disk
    disk=compute_v1.Disk(
        name=disk_name,
        source_image=image_self_link,
        #instance disk type (default is pd-balanced)
        type_=f"zones/{zone}/diskTypes/{GCP_DISK_TYPE}"
    )
    op=disks_client.insert(project=project_id,zone=zone,disk_resource=disk)
    op.result()

    #attach disk to instance
    attach_op=instances_client.attach_disk(
        project=project_id,
        zone=zone,
        instance=instance_name,
        #googles specific location of users chosen gcp image disk
        attached_disk_resource=compute_v1.AttachedDisk(source=f"zones/{zone}/disks/{disk_name}")
    )
    #wait for attachment of disk to complete
    attach_op.result()

    return disk_name

#get workers external ip to send ssh requests
def gcp_get_ip(instances_client,project_id,zone,instance_name):

    instance=instances_client.get(
        project=project_id,
        zone=zone,
        instance=instance_name
    )
    return instance.network_interfaces[0].access_configs[0].nat_i_p



def gcp_wait_for_ssh(ip,private_key,timeout=120):

    print("[!] Waiting for worker to setup ssh connection")
    wait=0

    #try to connect to worker for max 2minutes
    while wait<timeout:
        try:
            #create ssh client
            client=paramiko.SSHClient()
            #get trust
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            #default username is talos a single connect request will only last 10 seconds
            client.connect(ip,username="talos",pkey=private_key,timeout=10)
            client.close()
            print("[+] Worker instance online")
            return True
        
        #retry after 5 seconds
        except Exception as e:
            print(f"[!] Connection failure: {e}. Retrying...")
            time.sleep(5)
            wait+=5

    print("[-] Timed out while waiting for ssh setup")
    return False

#same logix as aws_run_command
def gcp_run_command(ip,private_key,commands,timeout=600):

    try:

        client=paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip,username="talos",pkey=private_key,timeout=30)

        full_command=" &&".join(commands) #combine commands to 1 run next only if prev succeedes

        stdin,stdout,stderr=client.exec_command(full_command,timeout=timeout)

        #input=stdout.read().decode()
        output=stdout.read().decode()
        error=stderr.read().decode()

        exit_code=stdout.channel.recv_exit_status()
        client.close()

        if exit_code==0:
            return True,output,error
        else:
            return False,output,error
        
    except Exception as e:
        print("[-] Command failed to run\n")
        return False,"",str(e)

def gcp_cleanup(instances_client,disks_client,project_id,zone,instance_name,disk_name):

    print("[!] Terminating GCP resources...")

    if instance_name:
        try:
            op=instances_client.delete(project=project_id,zone=zone,instance=instance_name)
            op.result()
            print(f"[+] Instance {instance_name} successfully deleted")

        except Exception as e:
            print(f"[-] Could not delete instance {instance_name}: {e}. Please delete manually")

    if disk_name:    
        try:
            op=disks_client.delete(project=project_id,zone=zone,disk=disk_name)
            op.result()
            print(f"[+] Disk {disk_name} deleted successfully")

        except Exception as e:
            print(f"[-] Could not delete disk {disk_name}: {e}. Please delete manually")

    print("[+] Cleanup completed successfully")
    return




def gcp_scan_image(image_name,bucket_name,project_id,zone="us-east1-b",service_account=None,image_project=None):

    #create clients to manage vm/instance,disks,images and buckets
    instances_client=compute_v1.InstancesClient()
    disks_client=compute_v1.DisksClient()
    images_client=compute_v1.ImagesClient()
    storage_client=storage.Client()

    #track if created
    created_instance=None
    created_disk=None

    #normalize names and limit to 63 characters cuz of google restrictions
    instance_name=f"talos-worker-{image_name}".replace("_","-").replace(".","-")[:63]
    disk_name=f"talos-disk-{image_name}".replace("_","-").replace(".","-")[:63]

    #grab the acount mail prefers the flag (if given) else env var. please read readme file
    service_acc_mail=service_account or os.environ.get("TALOS_GCP_SERVICE_ACCOUNT")

    if not service_acc_mail:
        print("[-] Account email is not set.Please read readme file for setting up")
        return None

    #image project=whole path to image, image id=users personal project image
    image_project=image_project or project_id

    try:
        #target image to scan
        image_self_link=gcp_get_source_image(images_client,image_project,image_name)
        if not image_self_link:
            print("[-] Failed while retrieving image")
            return None

        #ssh connection estabilishment
        key,public_key_str=gcp_generate_keypair()

        created_instance=gcp_launch_worker(instances_client,project_id,zone,instance_name,service_acc_mail,public_key_str)
        print(f"[+] Worker instance launched successfully with name: {created_instance}")

        created_disk=gcp_create_attach_disk(disks_client,instances_client,project_id,zone,image_self_link,created_instance,disk_name)
        print(f"[+] Disk: {created_disk} attached and running successfully")

        ip=gcp_get_ip(instances_client,project_id,zone,created_instance)

        if not gcp_wait_for_ssh(ip,key):
            print("[-] Worker did not respond with SSH ")
            return None

        print("[!] Prepairing worker...")
        #connect and mount image
        ok,out,err=gcp_run_command(ip,key,[
            "sudo mkdir -p /mnt/target",
            "sudo mount -o ro /dev/sdb1 /mnt/target"
        ])

        if not ok:
            print(f"[-] Failed to prepare and mount disk: {err}")
            return None
        else:
            print("[+] Worker preperation successfull")

        print("[+] Installing talos on worker...")
        ok,out,err=gcp_run_command(ip,key,[
            "sudo apt-get update -qq",
            "sudo apt-get install -y git",
            "git clone https://github.com/m0kall/talos.git",
            "cd talos",
            "chmod +x install.sh",
            "sudo ./install.sh"],timeout=900)
        if not ok:
            print(f"[-] Installation of talos failed: {err}\n")
            return None
        print("[+] Talos installation on worker completed successfully")

        #name normalization again ("/"" will break paths etc on google)
        normalized_image=image_name.replace("/","_")

        print("[!] Scanning image on worker. This might take a while...")
        remote_script=(
            "import talos\n"
            "from google.cloud import storage\n"
            f"sbom=talos.generate_sbom_from_mounted_path('/mnt/target','{normalized_image}',talos.BASE_DIR)\n"
            "scan_paths=talos.scan_img(sbom) if sbom else None\n"
            f"merged=talos.save_merged(scan_paths,'{normalized_image}',talos.BASE_DIR) if scan_paths else None\n"
            "if merged:\n"
            f"    storage.Client().bucket('{bucket_name}').blob('{normalized_image}-merged.json').upload_from_filename(merged)\n"
             "    print('UPLOAD_OK')\n"
            "else:\n"
            "    print('SCAN_FAILED')\n"
        )

        ok,out,err=gcp_run_command(ip,key,[
            "cd talos",
            f"cat>online_run.py<<'PYEOF'\n{remote_script}\nPYEOF\nsudo python3 online_run.py"
            #"sudo python3 online_run.py"
        ],timeout=1800)#if you change any default constants like instance type etc consider changing timeout time here.with our defaults the scan should take around 15minutes

        if not ok or "UPLOAD_OK" not in out:
            print(f"[-] Remote scan and results upload failed: {out}\n{err}")
            return None

        local_dir=BASE_DIR/"merged"
        local_dir.mkdir(exist_ok=True)
        local_file=local_dir/f"{normalized_image}-merged.json"

        #download from bucket and delete file from bucket
        bucket=storage_client.bucket(bucket_name)
        blob=bucket.blob(f"{normalized_image}-merged.json")
        blob.download_to_filename(str(local_file))
        blob.delete()

        print(f"[+] Scan completed successfully! Results downloaded at: {local_file}")
        return str(local_file)
    
    except Exception as e:
        print(f"[-] Critical error while running scans on worker machine: {e}")
        print("Note that some scans might have been completed while others not.")
        return None

    finally:
        gcp_cleanup(instances_client,disks_client,project_id,zone,created_instance,created_disk)


    return

#local scan logic
def scan_img(sbom_path):
    print(f"[+] Scanning SBOM: {sbom_path}")

    if sbom_path is None:
        print(f"[-] Missing SBOM file ")  
        return None
    
    sbom_path = str(sbom_path)

    scan_dir = BASE_DIR / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)

    #normalize name
    imageName = Path(sbom_path).stem.replace(".cdx", "")
    #imageName = Path(sbom_path).stem.replace(".cdx"," ")

    #output files path
    trivy_out = scan_dir / "trivy" / f"{imageName}-trivy.json"
    grype_out = scan_dir / "grype" / f"{imageName}-grype.json"
    osv_out   = scan_dir / "osv-scanner" / f"{imageName}-osv.json"

    #ensure folders exists
    trivy_out.parent.mkdir(parents=True, exist_ok=True)
    grype_out.parent.mkdir(parents=True, exist_ok=True)
    osv_out.parent.mkdir(parents=True, exist_ok=True)

    #run scanners
    try:
        #trivy
        print("Scanning Using Trivy...")
        subprocess.run(

            ["trivy", "sbom", "-f", "json", "-o",str(trivy_out),sbom_path],check=True
        )
        #grype and catch result from stdout
        print("Scanning Using Grype...")
        with open(grype_out, "w") as f:
            subprocess.run(
                ["grype", f"sbom:{sbom_path}", "-o", "json"],
                check=True,
                stdout=f
    )
        #osvscanner and catch result from stdout
        print("Scanning Using OSV-Scanner...")
        with open(osv_out, "w") as f:
            osvresult= subprocess.run(
                
                ["osv-scanner", "--format", "json", "-L", sbom_path],
                check=False, #osv returns 1 even when worked correctly :/
                stdout=f,
                stderr=subprocess.DEVNULL #cleanup osv file from warnings at the top of the file to not bombard user with garbage
    )
        #osv returns 1 if found vulnerabilities,2 for errors,0 for no vulnerabilities    
        if osvresult.returncode >1:
            print(f"[-] OSV-scanner failed with exit code {osvresult.returncode}")

        print("[+] Scans completed successfully")
        return {"trivy":str(trivy_out),"grype":str(grype_out),"osv":str(osv_out),}

    except Exception as e :
        print(f"[-] Scanning Failed: {e}")
        return None

#master-agent image scan for aws provider
#default region is us-east-1 and volumes/instances goe to us-east-1a
#default profile name is talos-ssm-profile.this can be changed by using argument --profile while running talos
def aws_scan_image(ami_id,bucket_name,profile_name="talos-ssm-profile",region="us-east-1"):
    
    #default to a to zone of target region
    #availability_zone=f"{region}a"

    session=boto3.Session(region_name=region) #credentias configured using env vars
    ec2=session.client("ec2")
    ssm=session.client("ssm")
    s3=session.client("s3")
    #track if created
    instance_id=None
    volume_id=None

    #this looksup the availability zones for our region and defalts to the first one we see
    #during testing using default region us-east-1 this returs us-east-1a
    try:
        zones=ec2.describe_availability_zones(Filters=[{"Name":"region-name","Values":[region]}])
        availability_zone=zones["AvailabilityZones"][0]["ZoneName"]

    except Exception as e:
        print(f"[-] Could not retrieve availability zones for region {region}: {e}")
        return None


    try:
        snapshot_id=aws_get_snapshot_id(ec2,ami_id)
        if not snapshot_id:
            print("[-] Snapshot id retrieval failed")
            return None
        
        instance_id=aws_launch_worker(ec2,profile_name,availability_zone)
        if not instance_id:
            print("[-] Instance retrieval failed")
            return None
        
        print(f"[+] Worker instance launched successfully with id: {instance_id}")

        #wait for instance to reach running state (dont attach while instance is pending)
        ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])

        volume_id=aws_create_and_attach_volume(ec2,snapshot_id,instance_id,availability_zone)
        if volume_id:
            print(f"[+] Volume {volume_id} attached and running successfully")

        if not aws_wait_for_ssm(ssm,instance_id):
            print("[-] Critical error when waiting for ssm response!")
            return None
        
        #after setup is complete we send the commands to our created instance on aws
        #first set of commands is to set proper sizes for ram and mount the ami we want to scan (target folder)
        #this returns status (ok,True/False) output(out) and error message if any(err)
        print("[!] Prepairing worker....")
        ok, out, err= aws_run_command(ssm, instance_id, [
            #f"sudo fallocate -l {SWAP_SIZE}G /swapfile",
            #"sudo chmod 600 /swapfile",
            #"sudo mkswap /swapfile",
            #"sudo swapon /swapfile",
            "sudo mkdir -p /mnt/target",
            "sudo mount -o ro /dev/nvme1n1p1 /mnt/target"
        ])

        if not ok:
            print(f"[-] Failed to prepare and mount volume: {err}")
            return None
        else:
            print("[+] Worker set-up is complete")
        
        #second set of commands is for installing talos
        print("[!] Installing Talos on worker...")
        ok, out, err= aws_run_command(ssm, instance_id, [
            "sudo apt-get update",
            "sudo apt-get install -y git",
            "cd /home/ubuntu",
            "git clone https://github.com/m0kall/talos.git",
            "cd talos",
            "chmod +x install.sh",
            "./install.sh"
        ])

        if not ok:
            print(f"[-]Talos installation on worker failed: {err}\n")
            return None
        else:
            print("[+] Talos installation completed")
        
        
        #ami name normalization
        image_name=ami_id.replace("/","_")

        #final set of commands is creating a script that runs talos and scan the ami from the mounted volume
        #the result json is uploaded to the provided s3 bucket
        print("[!] Scanning AMI on worker.This might take a while...")
        remote_script= (
            "import talos, boto3\n"
            f"sbom = talos.generate_sbom_from_mounted_path('/mnt/target', '{image_name}', talos.BASE_DIR)\n"
            "scan_paths = talos.scan_img(sbom) if sbom else None\n"
            f"merged = talos.save_merged(scan_paths, '{image_name}', talos.BASE_DIR) if scan_paths else None\n"
            "if merged:\n"
            f"    boto3.client('s3').upload_file(merged, '{bucket_name}', '{image_name}-merged.json')\n"
            "    print('UPLOAD_OK')\n"
            "else:\n"
            "    print('SCAN_FAILED')\n"
        )
        #this runs the above script timeout time is 15 minutes since scanning can take a while
        ok, out, err= aws_run_command(ssm, instance_id, [
            "cd /home/ubuntu/talos",
            f"cat > online_run.py << 'PYEOF'\n{remote_script}PYEOF",
            "python3 online_run.py"
        ], timeout=900)

        if not ok or "UPLOAD_OK" not in out:
            print(f"[-] Remote scan and upload of results failed: {out}\n{err}")
            return None
        
        #local save directory
        local_dir=BASE_DIR/"merged"
        local_dir.mkdir(exist_ok=True)
        local_file=local_dir/f"{image_name}-merged.json"
        
        #download,save results to directory and clean file from bucket
        s3.download_file(bucket_name,f"{image_name}-merged.json",str(local_file))
        s3.delete_object(Bucket=bucket_name,Key=f"{image_name}-merged.json")

        print(f"[+] Online scan completed successfully! Results saved at: {local_file}")
        return str(local_file)
    
    #just in case there is a session error or anything, report to user
    except Exception as e:
        print(f"[-]Critical error while running scans on worker machine: {e}.\n[!] Note that some scans might have been completed while others not started.Please check and try again.")
        return None
    
    #whatever happens either failed or successful scan we always terminate the instance and bucket
    finally:
        aws_cleanup(ec2,instance_id,volume_id)
            

#used for sorting cves at display image function
def get_sort_value(r):
    if r[4] != "N/A":
        return float(r[4])
    else:
        return float("inf")

#shows almost all info on cves from 1 image
#the default values of display can be changed by the user for better visibility. talos by default displays 50 entries with high and critical severity
def display_image(path, limit=50,severity_filter="high"):

    if not Path(path).exists():
        print(f"[-] File does not exist. Please check if path: {path} is correct")
        return

    with open(path,encoding="utf-8") as f:
        data= json.load(f)

    stats=data.get("stats",{})
    cves=data.get("found_vulnerabilities",{})

    if not cves:
        print("[-] File contains no vulnerabilities")
        return
    
    image_name=Path(path).stem.replace("-merged","")

    print(f"\n+{'-'*48} Image {image_name} information{'-'*48}+")
    print(f"Total CVEs: {stats.get('total_cves', 'N/A')}")
    print(f"Max Risk Factor: {stats.get('max_risk_factor','N/A')}")
    print(f"Max CVSS score: {stats.get('max_cvss', 'N/A')}")
    print(f"Max Risk CVE: {stats.get('max_risk_factor_cve', 'N/A')}")
    print(f"+{'-'*182}+")

    #build table
    rows=[]

    for cve_id, cve in cves.items():

        package= cve.get("package", {})
        pkg_name= package.get("name") or "N/A"
        cvss= cve.get("cvss_score")
        epss_pct= cve.get("epss_percentile")
        risk= cve.get("risk_factor")

        if cvss is not None:
            cvss_str= str(cvss)

        else:
            cvss_str= "N/A"

        if epss_pct is not None:
            epss_pct_str= f"{epss_pct*100:.2f}%" #round to 2 decimals for better visibility

        else:
            epss_pct_str="N/A"

        if risk is not None:    
            risk_str=str(risk)
        else:
            risk_str="N/A"

        #fixed version can be either a list or a string depending on the scanner
        fixed= cve.get("fixed_version")
        if fixed:
            if isinstance(fixed,list):
                fixed_str=", ".join(fixed) #joining the strings when its a list gets rid of some unessessarty symbols
            else:
                fixed_str=str(fixed)
        else:
            fixed_str="N/A"        


        rows.append([
            cve_id,
            cve.get("severity", "UNKNOWN"),
            cvss_str,
            epss_pct_str,
            risk_str,
            pkg_name,
            fixed_str
        ])

    #filter results if many entries
    if severity_filter.lower() =='all':
        pass #if user picks no filter we just sort using risk factor

    #default value displays high and critical severities
    elif severity_filter.lower()=="high":    
        rows=[r for r in rows if r[1] in ("CRITICAL","HIGH")]

    else:

        rows=[r for r in rows if r[1]==severity_filter.upper()]

    #sort by risk factor. N/A values go to the bottom of the list/row
    #by using key= we call this function for every row 1by1
    rows.sort(key=get_sort_value)

    #apply limit
    total_filtered=len(rows)
    rows=rows[:limit]

    headers = ["CVE ID", "Severity", "CVSS", "EPSS percentile", "Risk Factor", "Package", "Fixed Version"]
    
    print("[!] Note: CVEs with no risk factor are shown at the end of the table")
    print(f"Showing {len(rows)} of {total_filtered} CVEs")
    print(tabulate(rows, headers=headers, tablefmt="grid"))

    return

#shows the comparison between all images
def display_all():

    merged_dir= BASE_DIR/"merged"

    if not merged_dir.exists():
        print("[-] Directory does not exist. Run talos scan first")
        return
    
    imgs=list(merged_dir.glob("*-merged.json"))
    
    if not imgs:
        print("[-] Cannot find scan results to combine. Run talos scan first")
        return
    
    #build table
    rows=[]

    for img in imgs:

        with open(img,encoding="utf-8") as f:
            
            data=json.load(f)

        stats=data.get("stats",{})
        image_name= img.stem.replace("-merged","")
        
        total_cves= stats.get("total_cves","N/A")
        max_risk=stats.get("max_risk_factor", None)
        max_cvss=stats.get("max_cvss",None)
        max_epss_prc=stats.get("max_epss_percentile", None)
        top_risk_cve=stats.get("max_risk_factor_cve", "N/A")

        if max_risk is not None:
            risk_str=str(max_risk)
        
        else:
            risk_str="N/A"
        

        if max_cvss is not None:
            cvss_str=str(max_cvss)
        
        else:
            cvss_str="N/A"

        if max_epss_prc is not None:
            max_epss_prc_str=f"{max_epss_prc*100:.2f}%"
        
        else:
            max_epss_prc_str="N/A"

        rows.append([image_name,total_cves,cvss_str,max_epss_prc_str,risk_str,top_risk_cve])

    rows.sort(key=get_sort_value)

    #add ranking number to each image in each row
    for index,row in enumerate(rows):
        row.insert(0,index+1) #add the rank to row and other rows are now row+1 in position

    print("\n Images ranked by safest to most dangerous (ascending order by max risk factor)\n")
    print(f"\n+{'-'*92} Image Risk Comparison{'-'*92}+")
    headers=["Rank","Image","Found CVEs","Max CVSS value","Max EPSS%","Max Risk Factor","Riskiest CVE"]
    print(tabulate(rows,headers=headers,tablefmt="grid"))
    print(f"\n\n+{'-'*206}+\n")
    print(f"\n Total Images:{len(rows)}\n\n")

    return

#same as get_sort_value but for list of dicts (used in export function)
def get_cve_sort_value(cve):

    risk=cve.get("risk_factor")

    if risk is not None:
        return risk
    else:
        return float("inf")


def exportall():
    
    merged_dir= BASE_DIR/"merged"
    results_dir= BASE_DIR/"results"

    if not merged_dir.exists():
        print("[-] No merged results found. Please run talos scan")
        return
    
    #grab all merged files
    files=list(merged_dir.glob("*-merged.json"))
    
    if not files:
        print("[-] No merged files found.")
        return
        
    #create folder if not already there
    results_dir.mkdir(exist_ok=True)

    #timestamp format is year month day_hour minutes seconds just like sboms format
    timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")

    #output file
    output=results_dir/f"talos_report_{timestamp}.xlsx"

    #creating the excel file contents
    new_workbook=openpyxl.Workbook()

    ###this is the 1st sheet containing all the images and comparisons
    sheet1= new_workbook.active #edit the default/first sheet to not get 3 sheets (1st empty)
    sheet1.title="Image Comparison"

    #headers rows etc. same logic as display functions
    sheet1.append(["Rank","Image","Total CVEs","Max CVSS","Max EPSS%"," Max Risk Factor","Riskiest CVE"])

    image_rows=[]

    for file in files:
        with open(file,encoding="utf-8") as f:
            data=json.load(f)

        stats=data.get("stats",{})
        image_name=file.stem.replace("-merged","")

        total_cves= stats.get("total_cves","N/A")
        max_risk=stats.get("max_risk_factor", None)
        max_cvss=stats.get("max_cvss",None)
        max_epss_prc=stats.get("max_epss_percentile", None)
        top_risk_cve=stats.get("max_risk_factor_cve", "N/A")

        if max_risk is not None:
            risk_str=str(max_risk)
        else:
            risk_str="N/A"
        

        if max_cvss is not None:
            cvss_str=str(max_cvss)
        else:
            cvss_str="N/A"

        if max_epss_prc is not None:
            max_epss_prc_str=f"{max_epss_prc*100:.2f}%"
        else:
            max_epss_prc_str="N/A"

        image_rows.append([image_name,total_cves,cvss_str,max_epss_prc_str,risk_str,top_risk_cve])
    image_rows.sort(key=get_sort_value)

    for index, row in enumerate(image_rows):
        sheet1.append([index+1]+row)#unlike display function here we do a new list and we join it with the other rows. then we append the whole row to sheet1

    ###2nds sheet containing every info in found cves and in what image they were found
    sheet2=new_workbook.create_sheet(title="All CVEs Info")
    
    sheet2.append(["Image","CVE ID","Severity","CVSS Score","EPSS Score","EPSS Percentile","Risk Factor","Package","Package Version","Fixed Version","Found By","References","Description"])

    for file in files:
        with open(file,encoding="utf-8")as f:
            data=json.load(f)

        image_name=file.stem.replace("-merged","")
        cves=data.get("found_vulnerabilities",{})

        cve_list=list(cves.values())
        cve_list.sort(key=get_cve_sort_value)

        for cve in cve_list:

            package= cve.get("package", {})
            pkg_name= package.get("name") or "N/A"
            pkg_version=package.get("version")or "N/A"

            cvss= cve.get("cvss_score")
            epss_pct= cve.get("epss_percentile")
            risk= cve.get("risk_factor")
            found_by=" ,".join(cve.get("found_by",[]))

            references=cve.get("references",[])
            if references:
                references_str="; ".join(references)
            else:
                references_str="N/A"

            if cvss is not None:
                cvss_str= str(cvss)

            else:
                cvss_str= "N/A"

            if epss_pct is not None:
                epss_pct_str= f"{epss_pct*100:.2f}%" #round to 2 decimals for better visibility

            else:
                epss_pct_str="N/A"

            if risk is not None:    
                risk_str=str(risk)
            else:
                risk_str="N/A"

            #fixed version can be either a list or a string depending on the scanner
            fixed= cve.get("fixed_version")
            if fixed:
                if isinstance(fixed,list):
                    fixed_str=", ".join(fixed) #joining the strings when its a list gets rid of some unessessarty symbols
                else:
                    fixed_str=str(fixed)
            else:
                fixed_str="N/A"        

            sheet2.append([
                image_name,
                cve.get("id",""),
                cve.get("severity",""),
                cvss,
                cve.get("epss_score"), #we dont convert it to string so it can be used as a value for sorting in excel doc. if empty=no epss score
                epss_pct_str,
                risk_str,
                pkg_name,
                pkg_version,
                fixed_str,
                found_by,
                references_str,
                cve.get("description","")
            ])
    try:
        new_workbook.save(output)
        print(f"[+] Excel report saved at: {output}")
    
    except Exception as e:
        print(f"[+] Exporting failed: {e}")
        return

    return str(output)

#============================================================================= COMMAND HANDLING =======================================================================================
def handle_scan(args):

    #same logic as below but for aws provider
    if args.online: #scan --online

        #if not args.bucket:
        #    print("[-] Please also use --bucket <bucket_name> it is needed for downloading the results ")
        #    sys.exit(1)

        if args.image:#scan --online --image img/path
            handle_online_scan([args.image],args.bucket,args.gcp_bucket,args.profile,args.region,args.gcp_project,args.zone,args.service_account)
        
        elif args.file: #scan --online --file path/to/file

            if Path(args.file).exists():
                with open(args.file,"r") as f:
                    imgs=[line.strip() for line in f if line.strip()]
                    if not imgs:
                        print("[-] File does not contain any image identifiers")
                    else:
                        handle_online_scan(imgs,args.bucket,args.gcp_bucket,args.profile,args.region,args.gcp_project,args.zone,args.service_account)
            else:
                print(f"[-] File {args.file} does not exist")
        else:
            print(f"[-] This command requires either --image or --file")
        return

    if args.image: #scan --image img/path

        sbomPath= generate_sbom(args.image)
        if not sbomPath:
            print("[-] Critical error occured while generating SBOM")
            sys.exit(1)

        scan_path=scan_img(sbomPath)

        if scan_path:
            image_name= Path(sbomPath).stem.replace(".cdx","")
            save_merged(scan_path,image_name, BASE_DIR)

        else:
            print("[-] Critical error occured while scanning image")
            sys.exit(1)     


    #elif args.sbom: #scan --sbom sbompath 2do only for sbom?

    elif args.file: #scan --file path/to/file

        if Path(args.file).exists():
            with open(args.file, "r") as f:
                imgs= [line.strip() for line in f if line.strip()] #read lines ignore spaces
                if not imgs:
                    print("[-] File does not contain any image path")
                
                else:
                    for image in imgs:
                        #check if path exists
                        if not Path(image).exists():
                            print(f"[!] Skipped image {image} (not found)")
                            continue

                        print(f"\n[+] Scanning image: {image}")
                        sbomPath = generate_sbom(image)

                        if not sbomPath:
                            print(f"[!] SBOM generation failed for image {image}. Skipping...")
                            continue

                        scan_path=scan_img(sbomPath)
                        if scan_path:
                            image_name= Path(sbomPath).stem.replace(".cdx","")
                            save_merged(scan_path,image_name, BASE_DIR)

                        else:
                            print(f"[!] Cannot scan image {image}. Skipping...")
                            #continue 

        else:
            print(f"[-] Error, file {args.file} does not exist")

    else:
        print("[-] You must provide an argument. Please read help menu with talos -h for more information")

def handle_display(args):
    if args.image:
        display_image(args.image, args.limit,args.severity)

    elif args.all:
        display_all()

    else:
        print("[-] You must provide an argument. Use 'talos display -h' for help")

#used for searching an image on a whole gcp path
def parse_gcp_identifier(image_id,fallback_project=None):

    #matches the whole string that contains the exact path of the scannable image
    match = re.match(r"^projects/([^/]+)/global/images/([^/]+)$", image_id)

    #if user gave us the full path return the info else return the value at --project
    if match:
        return match.group(1),match.group(2) #return path,image name

    if fallback_project:
        return fallback_project,image_id

    return None,None

#search an image on aws fullpath
def parse_aws_identifier(image_id,fallback_region=None):

    match = re.match(r"^arn:aws:ec2:([^:]+):(\d+):image/(ami-[0-9a-f]+)$", image_id)

    if match:
        return match.group(1),match.group(3) #return region,ami_id

    if image_id.startswith("ami-"):
        return fallback_region,image_id

    return None,None





#used for scanning either aws or gcp images
def handle_online_scan(identifiers,aws_bucket_name,gcp_bucket_name,profile_name,region="us-east-1",gcp_project=None,zone="us-east1-b",service_account=None):

    #loop through the whole list containing the images
    for identifier in identifiers:
        if "/" not in identifier:
            print(f"[!] Skipped {identifier}: Missing cloud prefix")
            continue

        #grab provider and image id by splitting the txt file on the first "/"
        provider,image_id=identifier.split("/",1)
        
        if provider=="aws":

            if not aws_bucket_name:
                print(f"[!] Skipped {identifier}: s3 bucket name required. Please use --awsbucket")
                continue


            #get arn "path" to ami id fallsback to users --region if not found
            resolved_region,ami_id=parse_aws_identifier(image_id,fallback_region=region)

            if not ami_id:
                print(f"[!] Skipped {identifier}: could not find ami id")
                continue
            
            print(f"[+] Scanning {identifier} via AWS...")
            result=aws_scan_image(ami_id,aws_bucket_name,profile_name,resolved_region)

            if not result:
                print(f"[-] Failed scanning {identifier}")


        elif provider=="gcp":

            if not gcp_project:
                print(f"[!] Skipped {identifier}: CGP project required. Please use --project")
                continue


            if not gcp_bucket_name:
                print(f"[!] Skipped {identifier}: GCS bucket name required. Please use --gcpbucket")
                continue

            #resolved project=where the image project is
            resolved_project,image_name=parse_gcp_identifier(image_id,fallback_project=gcp_project)

            if not resolved_project:
                print(f"[!] Skipped {identifier}: Invalid project.")
                continue


            print(f"[+] Scanning {identifier} via GCP...")
            result=gcp_scan_image(image_name,gcp_bucket_name,gcp_project,zone,service_account,image_project=resolved_project)

            if not result:
                print(f"[-] Critical error while scanning {identifier}")

        else:
            print(f"[!] Skipped {identifier}: unsupported provider")

    return

def handle_export(args):
    exportall()

#########


def main():

    parser = argparse.ArgumentParser(
    prog="talos",
    description="Talos - a VM image and SBOM vulnerability scanner"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands and arguments"
    )

    #======================================================================= All commands ============================================================================================
    scan_parser = subparsers.add_parser(
       "scan",
       help= "scan vm image or SBOM",
       description=(
           "If provided with an img file, generates SBOM then starts scanning it for vulnerabilities. " 
           "If provided with a SBOM starts immediately scanning for vulnerabilities. "
           "If provided with an txt file containing path to mult images, generate SBOM then starts scanning for vulnerabilities for each image inside the txt."                                                                       
       )
    )

    display_parser=subparsers.add_parser(
       "display",
       help= "Show results of scans with tables",
       description= "Show vulnerability results from previous scans"                                                                      
    )

    export_parser=subparsers.add_parser(
        "export",
        help="Exports all results to an Excel file",
        description=(
            "Reads merged results from scans and exports all the info to an Excel file. "
            "1st sheet shows general statistics "
            "2nd sheet shows a complete report of every vulnerability inside every image provided."
        )
    )

    #====================================================================================ARGUMENTS====================================================================================
    #available arguments for scan command
    scan_parser.add_argument(
        "--image",
        help="Provide path to image file to start generating SBOM and scan for vulnerabilities"
    )

    scan_parser.add_argument(
        "--profile",
        default="talos-ssm-profile",
        help="IAM instance profile name. This contains SSM and S3 permissions for the worker instance. Default name is talos-ssm-profile "
    )

    #2do?
    #scan_parser.add_argument(
    #    "--sbom",
    #    help="Provide path to SBOM file to scan vulnerabilities"
    #)
    
    scan_parser.add_argument(
        "--file",
        help="Provide path to textfile containing list of scannable images"
    )
    scan_parser.add_argument(
        "--project",
        dest="gcp_project", #overide for simplicity
        help="GCP project ID to use for the worker insance,disk and image lookup. Only needed if you are not using projects/projectid/... path"
    )
    scan_parser.add_argument(
        "--online",
        action="store_true",
        help="Scan a VM image directly from a cloud provider (aws/gcp.use cloud-prefixed identifiers please read readme file)"
    )
    scan_parser.add_argument(
        "--awsbucket",
        dest="bucket",
        help="S3 bucket name used to download scan results from the cloud worker AWS) "
    )

    scan_parser.add_argument(
        "--gcpbucket",
        dest="gcp_bucket",
        help="GCP GCS bucket name used to download scan results from the cloud worker GCP) "
    )

    scan_parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region to use for the worker instance,volume and snapshot lookup. Must match the region of target AMI. Defaults to us-east-1"
    )
    scan_parser.add_argument(
        "--zone",
        default="us-east1-b",
        help="GCP zone to use for the worker instance and disk. Must match the region of project. defaults to us-east1-b"
    )
    scan_parser.add_argument(
        "--serviceacc",
        dest="service_account",
        help="GCP service account email. If not given it falls back to TALOS_GCP_SERVICE_ACCOUNT enviromental variable. Please read readmefile"
    ) 

    #====arguments for display command
    display_parser.add_argument(
        "--image",
        help="Provide path to .json file to display its saved results"
    )

    display_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="limit the display results for better terminal visibility"
    )
    display_parser.add_argument(
        "--severity",
        default="high",
        help="sort the display results by severity (for better terminal visibility) You can choose between all,critical,high,medium,low. Default is high wich shows both critical and high severity"
    )

    display_parser.add_argument(
        "--all",
        action="store_true", #no value needed
        help="Display and compare results of all images. This reads everything on the merged folder and ranks images by risk (ascending)"
    )

    #read user input
    args = parser.parse_args()

    if args.command == "scan":
        handle_scan(args)
    elif args.command == "display":
        handle_display(args)
    elif args.command=="export":
        handle_export(args)
    if not args.command:
        parser.print_help()    

if __name__ == "__main__":
    main()