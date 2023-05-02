# serial-scanner

## Running via GitHub actions

1. Click on Actions
2. Choose Serial Scanner under All Workflows
3. Input the repo name in format owner/repo. Start the flow. 
4. Download the report once the scan is complete. 

## Running locally
### downloading repo and installing the dependencies
```
git clone https://github.com/Suraj-Freshworks/serial-scanner.git
cd serial-scanner
pip install -r requirements
```

### scanning the open-source repo
```
python main.py <GH_TOKEN> <REPO_NAME>
```

For generating **<GH_TOKEN>**, click on the **Settings** by clicking your profile icon on the top-left. Click on **Developer settings** and select Token (classic) under Personal Access Tokens menu. Add a note and check **public_repo** under scopes. Click on Generate token and copy the token generated. 

**<REPO_NAME>** should be of the format _Suraj-Freshworks/serialscanner_.

