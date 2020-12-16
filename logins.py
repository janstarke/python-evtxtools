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

import functools
import sys
import argparse
from evtx import PyEvtxParser
import xmltodict
from datetime import datetime
import progressbar
from enum import Enum


class LogonType(Enum):
    LOGIN_SUCCESS = 10,
    LOGIN_FAILURE = 11,
    LOGOUT = 20


class EventDescriptor:
    def __init__(self, type: LogonType, **kwargs):
        self.__type = type
        self.__properties = dict()
        self.__properties['logon_type'] = kwargs.get('logon_type')
        self.__properties['workstation_name'] = kwargs.get('workstation_name')
        self.__properties['target_user_name'] = kwargs.get('target_user_name')
        self.__properties['target_user_sid'] = kwargs.get('target_user_sid')
        self.__properties['target_logon_id'] = kwargs.get('target_logon_id')
        self.__properties['ip_address'] = kwargs.get('ip_address')
        self.__values = dict()

    def instantiate(self, event_data: dict):
        instance = EventDescriptor(self.type,**self.__properties)
        for property, event_entry in self.__properties.items():
            instance.__values[property] = event_data.get(event_entry)
        return instance

    @property
    def values(self):
        return self.__values

    @property
    def type(self) -> LogonType:
        return self.__type

    @property
    def logon_type(self):
        return self.__values['logon_type']

    @property
    def workstation_name(self) -> str:
        return self.__values['workstation_name']

    @property
    def target_user_name(self) -> str:
        return self.__values['target_user_name']

    @property
    def target_user_sid(self) -> str:
        return self.__values['target_user_sid']

    @property
    def target_logon_id(self) -> str:
        return self.__values['target_logon_id']

    @property
    def ip_address(self) -> str:
        return self.__values['ip_address']


EVENT_DESCRIPTORS = {
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
    4624: EventDescriptor(type=LogonType.LOGIN_SUCCESS,
                          logon_type='LogonType',
                          workstation_name='WorkstationName',
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId',
                          ip_address='IpAddress'),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634
    4634: EventDescriptor(type=LogonType.LOGOUT,
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId'),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4647
    4647: EventDescriptor(type=LogonType.LOGOUT,
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId')
}

@functools.total_ordering
class LoginSession:
    LOGON_TYPES = {
        2: "Interactive",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials",
        10: "RemoteInteractive",
        11: "CachedInteractive"
    }
    NO_TIME = "????-??-?? ??:??:??"

    def __init__(self, event_id: int, timestamp: datetime, event: EventDescriptor):
        self.__login_timestamp = None
        self.__login_event_id = None
        self.__login_event = None
        self.__logout_timestamp = None
        self.__logout_event_id = None
        self.__logout_event = None

        if event.type == LogonType.LOGIN_SUCCESS:
            self.__login_event_id = event_id
            self.__login_timestamp = timestamp
            self.__login_event = event
        elif event.type == LogonType.LOGOUT:
            self.__logout_event_id = event_id
            self.__logout_timestamp = timestamp
            self.__logout_event = event

        assert self.logged_in or self.logged_out

    def merge(self, event_id: int, timestamp: datetime, event: EventDescriptor):
        if self.logged_in and event.type == LogonType.LOGOUT:
            self.__logout_event_id = event_id
            self.__logout_timestamp = timestamp
            self.__logout_event = self.__merge_event_data(self.__logout_event, event)
        elif self.logged_out and event.type == LogonType.LOGIN_SUCCESS:
            self.__login_event_id = event_id
            self.__login_timestamp = timestamp
            self.__login_event = self.__merge_event_data(self.__login_event, event)
        else:
            my_event = self.__login_event if self.logged_in else self.__logout_event
            for key, value in event.values.items():
                if my_event.values.get(key) in (None, '-'):
                    my_event.values[key] = value

    @staticmethod
    def __merge_event_data(my_event: EventDescriptor, new_event: EventDescriptor) -> EventDescriptor:
        if my_event is None:
            return new_event
        for key, value in new_event.values.items():
            if my_event.values.get(key) in (None, '-'):
                my_event.values[key] = value
        return my_event

    @property
    def logged_out(self) -> bool:
        return self.__logout_timestamp is not None

    @property
    def logged_in(self) -> bool:
        return self.__login_timestamp is not None

    def __str__(self):
        return "%s - %s: %s login as %s from %s (%s)" % (
            self.login_time,
            self.logout_time,
            self.login_type,
            self.username,
            self.workstation_name,
            self.ip_address
        )

    @property
    def login_time(self):
        return self.__login_timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.__login_timestamp else self.NO_TIME

    @property
    def logout_time(self):
        return self.__logout_timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.__logout_timestamp else self.NO_TIME

    @property
    def login_type(self):
        return self.LOGON_TYPES[int(self.__login_event.logon_type)] if self.__login_event and self.__login_event.logon_type else "Unknown"

    @property
    def username(self):
        if self.__login_event:
            if self.__login_event.target_user_name:
                return self.__login_event.target_user_name
        if self.__logout_event:
            if self.__logout_event.target_user_name:
                return self.__logout_event.target_user_name
        return "unknown user"

    @property
    def workstation_name(self):
        if self.__login_event:
            if self.__login_event.workstation_name:
                return self.__login_event.workstation_name
        return '-'

    @property
    def ip_address(self):
        if self.__login_event:
            if self.__login_event.ip_address:
                return self.__login_event.ip_address
        return '-'

    @property
    def login_timestamp(self):
        return self.__login_timestamp

    @property
    def logout_timestamp(self):
        return self.__logout_timestamp

    @property
    def session_id(self):
        if self.__login_event:
            return self.__login_event.target_logon_id
        else:
            return self.__logout_event.target_logon_id

    def __eq__(self, other):
        if self.logged_in != other.logged_in:
            return False
        if self.logged_out != other.logged_out:
            return False
        if self.logged_in:
            return self.login_timestamp.__eq__(other.login_timestamp)
        elif self.logged_out:
            return self.logout_timestamp.__eq__(other.logout_timestamp)
        else:
            return False

    def __lt__(self, other):
        if self.logged_in == other.logged_in:
            if self.logged_in:
                return self.login_timestamp.__lt__(other.login_timestamp)
            elif self.logged_out:
                return self.logout_timestamp.__lt__(other.logout_timestamp)
            else:
                return False
        else:
            if other.logged_out:
                return other.logout_timestamp.__lt__(self.__login_timestamp)
            elif other.logged_in:
                return other.login_timestamp.__gt__(self.__logout_timestamp)


def exclude_event(event_data: dict) -> bool:
    return event_data['TargetUserSid'] in [
        'S-1-5-18',  # local system
        'S-1-5-7',  # anonymous
        'S-1-5-90-1',  # DWM-1
        'S-1-5-90-4'  # DWM-4
    ]

def parse_record_data(record_data: dict) -> dict:
    idx = record_data.find('\n')
    return xmltodict.parse(record_data[idx:])

def handle_record(event_data: dict, event_id: int, timestamp: datetime, sessions: dict):

    event = EVENT_DESCRIPTORS.get(event_id).instantiate(event_data)

    session = sessions.get(event.target_logon_id)
    if session is None:
        sessions[event.target_logon_id] = LoginSession(event_id, timestamp, event)
    else:
        session.merge(event_id, timestamp, event)

def print_logins(secfile, from_date, to_date):
    parser = PyEvtxParser(secfile)

    from_date = datetime.strptime(from_date, "%Y-%m-%d %H:%M:%S") if from_date else datetime.min
    to_date = datetime.strptime(to_date, "%Y-%m-%d %H:%M:%S") if to_date else datetime.max
    assert from_date <= to_date

    sessions = dict()
    for record in progressbar.progressbar(parser.records()):
        timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S.%f UTC")
        if timestamp < from_date or timestamp > to_date:
            continue
        record_data = parse_record_data(record['data'])
        event_id = int(record_data['Event']['System']['EventID'])

        if event_id in EVENT_DESCRIPTORS.keys():
            event_data = dict()
            for d in record_data['Event']['EventData']['Data']:
                event_data[d['@Name']] = d['#text']
            if not exclude_event(event_data):
                handle_record(event_data, event_id, timestamp, sessions)

    for s in sorted(sessions.values()):
        print(str(s))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='analyse user sessions')
    parser.add_argument('--evtx',
                        dest='secfile',
                        help='path of the Security.evtx file (default: stdin)',
                        type=argparse.FileType('rb'))

    parser.add_argument('--from',
                        dest='from_date',
                        help='timestamp pattern, where to start',
                        type=str)

    parser.add_argument('--to',
                        dest='to_date',
                        help='timestamp pattern, where to end',
                        type=str)

    args = parser.parse_args()
    secfile = args.secfile or sys.stdin

    print_logins(secfile, args.from_date, args.to_date)
