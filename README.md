# serial-scanner

## Running locally
### download repo and installing the dependencies
```
git clone https://github.com/Suraj-Freshworks/serial-scanner.git
cd serial-scanner
pip install -r requirements
```

### scanning the repo
`python serialscanner.py <GH_TOKEN> <REPO_NAME>`

For generating **<GH_TOKEN>**, click on the **Settings** by clicking your profile icon on the top-left. Click on **Developer settings** and select Token (classic) under Personal Access Tokens menu. Add a note and check **public_repo** under scopes. Click on Generate token and copy the token generated. 

**<REPO_NAME>** should be of the format _Suraj-Freshworks/serialscanner_.

