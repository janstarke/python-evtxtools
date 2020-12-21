import xml
from datetime import datetime

import progressbar
import xmltodict
from evtx import PyEvtxParser
from evtxtools.EventDescriptor import EVENT_DESCRIPTORS
from evtxtools.LoginSession import LoginSession
from evtxtools.RawEventList import RawEventList
from evtxtools.WellKnownSids import *
from evtxtools.WindowsEvent import WindowsEvent


class EvtxParser:
    pass


class EvtxParser:

    def __init__(self, files_to_scan: list, sid_filter: WellKnownSidFilter, from_date: datetime, to_date: datetime):
        self.__files_to_scan = files_to_scan
        self.__sid_filter = sid_filter
        self.__from_date = from_date
        self.__to_date = to_date
        self.__activities = dict()

    KNOWN_FILES = [
        'Security.evtx',
        'Microsoft-Windows-WinRM%4Operational.evtx',
        'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx'
    ]

    def exclude_event(self, event: WindowsEvent) -> bool:
        if 'TargetUserSid' in event.event_data:
            try:
                if self.__sid_filter.is_excluded(WellKnownSid(event.event_data['TargetUserSid'])):
                    return True
            except ValueError:
                pass

        if event.event_id not in EVENT_DESCRIPTORS:
            return True

        return False

    def parse_record_data(self, record_data: dict) -> dict:
        idx = record_data.find('\n')
        return xmltodict.parse(record_data[idx:])

    def handle_event(self, event: WindowsEvent):

        event_desc = EVENT_DESCRIPTORS.get(event.event_id).instantiate(event.event_data)

        session = self.__activities.get(event.activity_id)
        if session is None:
            self.__activities[event.activity_id] = LoginSession(event.event_id, event.timestamp, event_desc)
        else:
            session.merge(event.event_id, event.timestamp, event_desc)

    def parse_events(self):
        event_list = RawEventList(self.__files_to_scan, set(EVENT_DESCRIPTORS.keys()), self.__from_date, self.__to_date)
        for event in progressbar.progressbar(event_list):
            if not self.exclude_event(event):
                self.handle_event(event)

    def print_logins(self):
        for s in sorted(self.__activities.values()):
            print(str(s))

    def parse_record(self, record: dict):
        timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S.%f UTC")
        if timestamp < self.__from_date or timestamp > self.__to_date:
            return None

        try:
            record_data = self.parse_record_data(record['data'])
        except xml.parsers.expat.ExpatError:
            # TODO: print warning
            return None

        event_id = int(record_data['Event']['System']['EventID'])

        if event_id in EVENT_DESCRIPTORS.keys():
            event_data = dict()
            for d in record_data['Event']['EventData']['Data']:
                if isinstance(d, dict):
                    event_data[d['@Name']] = d['#text'] if '#text' in d else '-'
            if not self.exclude_event(event_data):
                activity_id = self.getCorrelationId(record_data)
                return self.handle_record(activity_id, event_data, event_id, timestamp)
