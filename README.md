# evtxtools

Collection of command line tools to correlate windows event logs. This set of tools is aimed to be used at forensic investigations.

## `login.py`

Parses `Security.evtx` and correlates logon and logoff events to display a user session timeline.

### Usage
```
usage: logins.py [-h] [--from FROM_DATE] [--to TO_DATE] [--include-local-system] [--include-anonymous] logsdir

analyse user sessions

positional arguments:
  logsdir               directory where logs are stored, e.g. %windir%\System32\winevt\Logs

optional arguments:
  -h, --help            show this help message and exit
  --from FROM_DATE      timestamp pattern, where to start
  --to TO_DATE          timestamp pattern, where to end
  --include-local-system
                        also show logins of the local system account
  --include-anonymous   also show logins of the anonymous account
```

### Example
```shell script
python logins.py ./evidence/winevt/Logs/ --from "2020-11-23 00:00:00" --to "2020-12-03 12:00:00"
```
