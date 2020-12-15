# evtxtools

## `login.py`

Parses `Security.evtx` and correlates logon and logoff events to display a user session timeline.

### Usage
```
usage: logins.py [-h] [--evtx SECFILE] [--from FROM_DATE] [--to TO_DATE]

analyse user sessions

optional arguments:
  -h, --help        show this help message and exit
  --evtx SECFILE    path of the Security.evtx file (default: stdin)
  --from FROM_DATE  timestamp pattern, where to start
  --to TO_DATE      timestamp pattern, where to end
```

### Example
```shell script
python logins.py --evtx ./Security.evtx --from "2020-11-30 18:00:00 UTC" --to "2020-12-03 12:00:00 UTC"
```