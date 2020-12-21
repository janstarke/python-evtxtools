import xml
from datetime import datetime

import progressbar
import xmltodict
import math
from evtx import PyEvtxParser
import threading, queue, os
from evtxtools.EventDescriptor import EVENT_DESCRIPTORS
from evtxtools.LoginSession import LoginSession
from evtxtools.WellKnownSids import *
from evtxtools.WindowsEvent import WindowsEvent


class EvtxParser:
    pass


class RawEventList:
    def __init__(self, files: list, included_event_ids: set, from_date: datetime, to_date: datetime):
        self.__files = files
        self.__included_event_ids = included_event_ids
        self.__from_date = from_date
        self.__to_date = to_date

    def __iter__(self):
        self.__events = dict()
        self.__queue = queue.Queue()
        self.__results = queue.Queue()
        self.__reader = None
        self.__reader_thread = threading.Thread(target=self.__event_reader_worker)
        self.__reader_thread.start()
        self.__workers = set()
        for _ in range(0, math.ceil(os.cpu_count() / 2)):
            th = threading.Thread(target=self.__event_parser_worker)
            self.__workers.add(th)
            th.start()
        return self

    def __next__(self):
        # if there are no workers anymore, no further results can be expected
        while len(self.__workers) > 0:
            # there are still workers, but maybe they return no result anymore
            try:
                return self.__results.get(timeout=1)
            except queue.Empty:
                continue
        try:
            return self.__results.get_nowait()
        except queue.Empty:
            raise StopIteration

    def __event_parser_worker(self):
        while True:
            record = None

            if self.__reader_thread is None:  # no records will ever be made available to be parsed
                try:
                    record = self.__queue.get_nowait()
                except queue.Empty:
                    # this may happen if another worker has removed the last remaining element
                    # after we have checked that the queue is not empty
                    self.__workers.remove(threading.current_thread())
                    return
            else:
                try:
                    record = self.__queue.get(timeout=1)
                except queue.Empty:
                    # this may happen if all records provided by the reader got consumed by other workers
                    continue
            assert record is not None

            try:
                self.__results.put(WindowsEvent(record,
                                                self.__included_event_ids,
                                                self.__from_date,
                                                self.__to_date))
            except WindowsEvent.IgnoreThisEvent:
                pass

            self.__queue.task_done()

    def __event_reader_worker(self):
        event = self.__get_next_record()
        while event is not None:
            self.__queue.put(event)
            event = self.__get_next_record()
        self.__reader_thread = None

    def __get_next_record(self):
        while len(self.__files) > 0 or self.__reader is not None:
            if self.__reader is None:
                self.__reader = PyEvtxParser(str(self.__files.pop())).records_json()

            try:
                return self.__reader.__next__()
            except StopIteration:
                self.__reader = None
        return None

    @staticmethod
    def __fill_queue(self, fstream):
        records = PyEvtxParser(fstream)
        for record in records.records():
            self.__queue.put(record)


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

    @staticmethod
    def __fill_queue(q, fstream):
        records = PyEvtxParser(fstream)
        for record in progressbar.progressbar(records.records()):
            q.put(record)

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
