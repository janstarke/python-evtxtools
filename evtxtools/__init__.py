import argparse
import os
from pathlib import Path

from evtxtools.WellKnownSids import *
from datetime import datetime


class readable_dir(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        prospective_dir=Path(values)
        if not prospective_dir.is_dir():
            raise argparse.ArgumentTypeError("{0} is not a valid path".format(prospective_dir))
        if os.access(prospective_dir, os.R_OK):
            setattr(namespace, self.dest, prospective_dir)
        else:
            raise argparse.ArgumentTypeError("{0} is not a readable dir".format(prospective_dir))

class creatable_file(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        prospective_file = Path(values)
        if prospective_file.exists():
            raise argparse.ArgumentTypeError("{0} already exists".format(prospective_file))
        if os.access(prospective_file.parent, os.W_OK):
            setattr(namespace, self.dest, prospective_file)
        else:
            raise argparse.ArgumentTypeError("{0} is not a writable dir".format(prospective_file.parent))


def parse_logins_arguments():
    parser = argparse.ArgumentParser(description='analyse user sessions')
    parser.add_argument('logsdir',
                        help='directory where logs are stored, e.g. %%windir%%\\System32\\winevt\\Logs',
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
    parser.add_argument('--latex-output',
                        dest='latex_output',
                        help='enable LaTeX output',
                        action='store_true')
    parser.add_argument('--hostname',
                        dest='hostname',
                        help='display this value as hostname',
                        type=str)
    args = parser.parse_args()
    return args

def parse_evtx2sqlite_arguments():
    parser = argparse.ArgumentParser(description='convert evtx files to sqlite database')
    parser.add_argument('logsdir',
                        help='directory where logs are stored, e.g. %%windir%%\\System32\\winevt\\Logs',
                        action=readable_dir)
    parser.add_argument('dbfile',
                        help="name of SQLite Database to be created",
                        action=creatable_file)
    args = parser.parse_args()
    return args


def parse_evtx2elasticsearch_arguments():
    parser = argparse.ArgumentParser(description='convert evtx files to an elasticsearch index')
    parser.add_argument('--override',
                        dest='override_index',
                        help='overrides an existing index, if it already exists',
                        action='store_true')
    parser.add_argument('logsdir',
                        help='directory where logs are stored, e.g. %%windir%%\\System32\\winevt\\Logs',
                        action=readable_dir)
    parser.add_argument('--index',
                        help="name of elasticsearch index",
                        type=str)
    args = parser.parse_args()
    return args