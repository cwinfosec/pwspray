# owa_spray
Password Spraying Utility designed for testing legacy OWA instances. 

## Example Usage

Attempt authentication as a single user:

```bash
python3 owa_spray.py -i 169.254.42.69 -d testdomain.local -u Administrator -p password
```

Attempt spray against multiple users:
```bash
python3 owa_spray.py -i 169.254.42.69 -d testdomain.local -U list_of_users.txt -p password
```

Attempt spray against multiple users, but wait 10 seconds between requests:
```bash
python3 owa_spray.py -i 169.254.42.69 -d testdomain.local -U list_of_users.txt -p password -j 10
```


Attempt spray against multiple users, and write results to `owa_spray.log`:
```bash
python3 owa_spray.py -i 169.254.42.69 -d testdomain.local -U list_of_users.txt -p password -o true
```

## Options


| Flag | Argument                       | Description                              |
| ---- | ------------------------------ | ---------------------------------------- |
| -h   | --help                         | Show the help menu                       |
| -i   | --ip \<IP_ADDRESS\>            | IP of OWA Instance                       |
| -d   | --domain \<domain.local\>      | Domain of target account                 |
| -u   | --username \<Username\>        | Username to target for password spraying |
| -U   | --User-list \<dictionary.txt\> | List of usernames for password spraying  |
| -p   | --password \<password\>        | The password to spray with               |
| -j   | --jitter \<0-99999\>           | Time to sleep between requests           |
| -o   | --out-file <True/unset>        | Write results to owa_spray.log           |


## To Do

- add flag for proxies
- clean-up output
- add/suppress verbosity
