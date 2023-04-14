#!/usr/bin/env python3

import json
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
parser.add_argument("branch_name", metavar="branch_name", type=str, help="branch_name")

args = parser.parse_args()

token = args.token
repo_name = args.repo_name
branch_name = args.branch_name

payload = {}
headers = {
  'Accept': 'application/vnd.github+json',
  'Authorization': 'Bearer '+token,
  'X-GitHub-Api-Version': '2022-11-28',
}

activate_url = "https://api.github.com/repos/" + repo_name + "/vulnerability-alerts"
activate_response = requests.request("PUT", activate_url, headers=headers, data=payload)
print(activate_response.text)

sleep(30)

alerts_url = 'https://api.github.com/repos/' + repo_name + '/dependabot/alerts'
alerts_response = requests.request("GET", alerts_url, headers=headers, data=payload).json()


def dependabot():
    count = 0
    dependabotIssues = []
    if len(alerts_response) == 0:
        pass
    else:
        for records in alerts_response:
            description = (records['security_advisory']['description']).replace('\n', '', 1).replace('`', '').replace(
                '_', '')
            path = records['dependency']['manifest_path']
            package = records['dependency']['package']['name']
            severity = records['security_advisory']['severity']
            vulnerableVersion = records['security_vulnerability']['vulnerable_version_range']
            cvss = records['security_advisory']['cvss']['score']
            summary = records['security_advisory']['summary']
            advisory = records['security_advisory']['ghsa_id']
            blank = ""
            dependabotIssues.append(
                [package, severity, cvss, summary, 'https://github.com/' + repo_name + '/tree/{branch_name}/' + path,
                 'https://github.com/advisories/' + advisory, blank, blank])
            count += 1
        # dependabot = tablib.Dataset(headers=['Package', 'Severity', 'CVSS', 'Summary', 'Description', 'Path', 'Reference','Status', 'Justification'])
        dependabot = tablib.Dataset(
            headers=['Package', 'Severity', 'Summary', 'Description', 'Path', 'Reference', 'Status', 'Justification'])
        print("Dependabot Findings: " + str(count))
        for i in dependabotIssues:
            dependabot.append(i)
        return dependabot


def semgrep():
    process = subprocess.run(["semgrep", "scan", "--config", "auto", "--json", "-q"], capture_output=True)
    json_data = json.loads(process.stdout)
    semgrepIssues = []
    count = 0
    if len(json_data) == 0:
        pass
    else:
        data = json_data['results']
        for record in data:
            ruleid = record['check_id']
            # confidence = record['extra']['metadata']['confidence']
            impact = record['extra']['metadata']['impact']
            # likelihood = record['extra']['metadata']['likelihood']
            severity = record['extra']['severity'].replace("ERROR", "HIGH").replace("WARNING", "MEDIUM").replace("INFO",
                                                                                                                 "LOW")
            # owasp = '\n'.join(record['extra']['metadata']['owasp'])
            startline = record['start']['line']
            endline = record['end']['line']
            # cwe = '\n'.join(record['extra']['metadata']['cwe'])
            path = record['path']
            message = record['extra']['message']
            reference = record['extra']['metadata']['source']
            blank = ""
            # semgrepIssues.append([ruleid, confidence, impact, likelihood, severity, message, f'https://github.com/{repo_name}/tree/{branch_name}/{path}#L{startline}-L{endline}', reference, owasp, cwe])
            semgrepIssues.append([ruleid, impact, message,
                                  f'https://github.com/{org_name}/{repo_name}/tree/{branch_name}/{path}#L{startline}-L{endline}',
                                  reference, blank, blank])
            count += 1

    # semgrep = tablib.Dataset(headers=['Ruleid', 'Confidence', 'Impact', 'Likelihood', 'Severity','Description', 'Path', 'Reference', 'OWASP', 'CWE', 'Status', 'Justification'])
    semgrep = tablib.Dataset(
        headers=['Ruleid', 'Severity', 'Description', 'Path', 'Reference', 'Status', 'Justification'])
    print("Semgrep Findings: " + str(count))
    for i in semgrepIssues:
        semgrep.append(i)
    return semgrep


timestr = time.strftime("%Y%m%d-%H%M%S")
book = tablib.Databook((dependabot(), semgrep()))
with open('SR' + timestr + '.xlsx', 'wb') as f:
    f.write(book.export('xlsx'))
