#!/usr/bin/env python3

import json
import os
import tablib
import time
import requests
import subprocess
import argparse
from time import sleep

"""""
Step-1.2 Examamine the data and flatten the data to 2D
"""""


parser = argparse.ArgumentParser("Argument Parser")
parser.add_argument("token", metavar="token", type=str, help="auth_token")
parser.add_argument("repo_name", metavar="repo_name", type=str, help="repo_name")
#parser.add_argument("branch_name", metavar="branch_name", type=str, help="branch_name")

args = parser.parse_args()

token = args.token
repo_name = args.repo_name
#branch_name = args.branch_name

dir_name = repo_name.split("/",1)[1]


fork_url = "https://api.github.com/repos/"+repo_name+"/forks"

payload = {}
headers = {
  'Accept': 'application/vnd.github+json',
  'Authorization': 'Bearer '+token,
  'X-GitHub-Api-Version': '2022-11-28',
}

url = "https://api.github.com/user"
token_response = requests.request("GET", url, headers=headers, data=payload)

if token_response.status_code == 200:
    print("Token is valid. Running script...")

    #fork repo in own account
    fork_response = requests.request("POST", fork_url, headers=headers, data=payload)
    #print(fork_response.json()['full_name'])

    repo_url = "https://github.com/"+repo_name+".git"

    if fork_response.status_code == 202:
        print("Repo forked successfully. The forked repo URL is: "+repo_url)

    #download the repo in local for semgrep scanning
    subprocess.call(["git","clone",repo_url])
    new_repoName = fork_response.json()['full_name']

    #get the branch name of the foreked repo
    branch_url = 'https://api.github.com/repos/'+new_repoName
    branch = requests.request("GET", branch_url, headers=headers, data=payload).json()
    branch_name = branch['default_branch']

    #enabling the dependabot alerts for the forked repo
    activate_url = 'https://api.github.com/repos/'+new_repoName+'/vulnerability-alerts'
    activate_response = requests.request("PUT", activate_url, headers=headers, data=payload)

    if activate_response.status_code == 204:
        print("Dependabot alerts succesfully enabled...")
    #print(activate_response.text)

    sleep(30)

    alerts_url = 'https://api.github.com/repos/'+new_repoName+'/dependabot/alerts'
    alerts_response = requests.request("GET", alerts_url, headers=headers, data=payload).json()

    def dependabot():
        count = 0 
        dependabotIssues = []
        dependabotIssuesHigh = []
        for records in alerts_response:
            #description = (records['security_advisory']['description']).replace('\n', '', 1).replace('`', '').replace('_', '')
            path = records['dependency']['manifest_path']
            package = records['dependency']['package']['name']
            severity = records['security_advisory']['severity']
            #vulnerableVersion = records['security_vulnerability']['vulnerable_version_range']
            cvss = records['security_advisory']['cvss']['score']
            summary = records['security_advisory']['summary']
            advisory = records['security_advisory']['ghsa_id']
            blank = ""
            dependabotIssues.append([package, severity, cvss, summary, 'https://github.com/'+repo_name+'/tree/'+branch_name+path, 'https://github.com/advisories/'+advisory, blank, blank])
            count += 1
            #if severity == "HIGH":
                 #dependabotIssuesHigh.append([package, severity, cvss, summary, 'https://github.com/'+repo_name+'/tree/'+branch_name+path, 'https://github.com/advisories/'+advisory, blank, blank])
        #dependabot = tablib.Dataset(headers=['Package', 'Severity', 'CVSS', 'Summary', 'Description', 'Path', 'Reference','Status', 'Justification'])
        dependabot = tablib.Dataset(headers=['Package', 'Severity','Summary', 'Description', 'Path', 'Reference','Status', 'Justification'])
        print("Dependabot Findings: "+str(count))
        for i in dependabotIssues:
            dependabot.append(i)
        return dependabot

    def semgrep():
        process = subprocess.run(["semgrep","scan","--config","auto","--json","-q"], capture_output=True, cwd=dir_name)
        json_data = json.loads(process.stdout)
        semgrepIssues = []
        count = 0
        data = json_data['results']
        for record in data:
            ruleid = record['check_id']
            #confidence = record['extra']['metadata']['confidence']
            impact = record['extra']['metadata']['impact']
            #likelihood = record['extra']['metadata']['likelihood']
            severity = record['extra']['severity'].replace("ERROR", "HIGH").replace("WARNING","MEDIUM").replace("INFO","LOW")
            #owasp = '\n'.join(record['extra']['metadata']['owasp'])
            startline = record['start']['line']
            endline = record['end']['line']
            #cwe = '\n'.join(record['extra']['metadata']['cwe'])
            path = record['path']
            message = record['extra']['message']
            reference = record['extra']['metadata']['source']
            blank = ""
            #semgrepIssues.append([ruleid, confidence, impact, likelihood, severity, message, f'https://github.com/{repo_name}/tree/{branch_name}/{path}#L{startline}-L{endline}', reference, owasp, cwe])
            semgrepIssues.append([ruleid, severity, message, f'https://github.com/{repo_name}/tree/{branch_name}/{path}#L{startline}-L{endline}', reference, blank, blank])
            count += 1
      
        #semgrep = tablib.Dataset(headers=['Ruleid', 'Confidence', 'Impact', 'Likelihood', 'Severity','Description', 'Path', 'Reference', 'OWASP', 'CWE', 'Status', 'Justification'])
        semgrep = tablib.Dataset(headers=['Ruleid', 'Severity', 'Description', 'Path', 'Reference', 'Status', 'Justification'])
        print ("Semgrep Findings: "+str(count))
        for i in semgrepIssues:
            semgrep.append(i)
        return semgrep

    file_name = 'output.xlsx'
    book = tablib.Databook((dependabot(),semgrep()))
    with open(file_name, 'wb') as f:
        f.write(book.export('xlsx'))
        print("Results successfully exported to "+file_name)

else:
    print("Invalid token. Please generate a new PAT!!! ")



