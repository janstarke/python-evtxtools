# evtxtools

Collection of command line tools to correlate windows event logs. This set of tools is aimed to be used at forensic investigations.

## `evtx2elasticsearch.py`

Imports Windows event logs (`evtx` files) into an elasticsearch index, using the [Elasticsearch Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)

_No index pattern is required anymore :-)_

### Usage

```
usage: evtx2elasticsearch.py [-h] [--override] [--index INDEX] logsdir

convert evtx files to an elasticsearch index

positional arguments:
  logsdir        directory where logs are stored, e.g. %windir%\System32\winevt\Logs

optional arguments:
  -h, --help     show this help message and exit
  --override     overrides an existing index, if it already exists
  --index INDEX  name of elasticsearch index
```

## `logins.py`

Parses `evtx` files and correlates logon and logoff events to display a user session timeline.

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
