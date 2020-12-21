import argparse

from logins import readable_dir
from evtxtools.WellKnownSids import *
from datetime import datetime

def parse_arguments():
    parser = argparse.ArgumentParser(description='analyse user sessions')
    parser.add_argument('logsdir',
                        help='directory where logs are stored, e.g. %windir%\\System32\\winevt\\Logs',
                        action=readable_dir)
    parser.add_argument('--from',
                        dest='from_date',
                        help='timestamp pattern, where to start',
                        type=datetime.fromisoformat,
                        default=datetime.min)
    parser.add_argument('--to',
                        dest='to_date',
                        help='timestamp pattern, where to end',
                        type=datetime.fromisoformat,
                        default=datetime.max)
    parser.add_argument('--include-local-system',
                        dest='include_local_system',
                        help='also show logins of the local system account',
                        action='store_true')
    parser.add_argument('--include-anonymous',
                        dest='include_anonymous',
                        help='also show logins of the anonymous account',
                        action='store_true')
    args = parser.parse_args()
    return args