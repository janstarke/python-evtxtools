"""
logins.py

Parses Security.evtx and correlates logon and logoff events to display a user
session timeline.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import os
from datetime import datetime

from pathlib import Path

from evtxtools.EvtxParser import EvtxParser
import evtxtools


class readable_dir(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        prospective_dir=Path(values)
        if not prospective_dir.is_dir():
            raise argparse.ArgumentTypeError("readable_dir:{0} is not a valid path".format(prospective_dir))
        if os.access(prospective_dir, os.R_OK):
            setattr(namespace, self.dest, prospective_dir)
        else:
            raise argparse.ArgumentTypeError("readable_dir:{0} is not a readable dir".format(prospective_dir))


def main():
    args = evtxtools.parse_arguments()
    sid_filter = evtxtools.WellKnownSidFilter()

    if args.include_local_system:
        sid_filter.include_local_system()
    if args.include_anonymous:
        sid_filter.include_anonymous()

    files_to_scan = list(filter(
        lambda f: f.is_file(), map(
            lambda sf: args.logsdir / sf,
            EvtxParser.KNOWN_FILES
        )
    ))
    evtx_parser = EvtxParser(files_to_scan, sid_filter, args.from_date, args.to_date)
    evtx_parser.parse_events()
    evtx_parser.print_logins()


if __name__ == '__main__':
    main()
