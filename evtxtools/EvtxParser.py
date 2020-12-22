import xml
from datetime import datetime

import progressbar
from evtx import PyEvtxParser
from evtxtools.EventDescriptor import EVENT_DESCRIPTORS
from evtxtools.Activity import Activity
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
        'System.evtx',
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

    def handle_event(self, event: WindowsEvent):
        activity = self.__activities.get(event.activity_id)
        if activity is None:
            activity = Activity()
            self.__activities[event.activity_id] = activity
        activity.add_event(event)

    def parse_events(self):
        event_list = RawEventList(self.__files_to_scan, set(EVENT_DESCRIPTORS.keys()), self.__from_date, self.__to_date)
        for event in progressbar.progressbar(event_list):
            if not self.exclude_event(event):
                self.handle_event(event)

    def print_logins(self):
        for s in sorted(self.__activities.values()):
            print(str(s))