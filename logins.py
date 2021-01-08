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

from evtxtools.EvtxParser import EvtxParser
import evtxtools


def main():
    args = evtxtools.parse_logins_arguments()
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
    evtx_parser.print_logins(enable_latex=args.latex_output)


if __name__ == '__main__':
    main()
