import requests
import argparse


parser = argparse.ArgumentParser("Argument Parser")
parser.add_argument("token", metavar="token", type=str, help="auth_token")
parser.add_argument("repo_name", metavar="repo_name", type=str, help="repo_name")
parser.add_argument("branch_name", metavar="branch_name", type=str, help="branch_name")

args = parser.parse_args()

token = args.token
repo_name = args.repo_name
branch_name = args.branch_name

url = f'https://api.github.com/repos/{repo_name}/dependabot/alerts'

payload={}
headers = {
  'Accept': 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
  'Authorization': 'Bearer '+token,
}

response = requests.request("GET", url, headers=headers, data=payload).json()

count = 0 
dependabotIssues = []
for records in response:
        description = (records['security_advisory']['description']).replace('\n','',1).replace('`','').replace('_','')
        path = records['dependency']['manifest_path']
        package = records['dependency']['package']['name']
        severity = records['security_advisory']['severity']
        vulnerableVersion = records['security_vulnerability']['vulnerable_version_range']
        cvss = records['security_advisory']['cvss']['score']
        summary = records['security_advisory']['summary']
        advisory = records['security_advisory']['ghsa_id']
        blank = ""
        dependabotIssues.append([package, severity, cvss, summary, description, f'https://github.com/{repo_name}/tree/{branch_name}/'+path, 'https://github.com/advisories/'+advisory, blank, blank])
        count += 1
print(count)
print(dependabotIssues)
