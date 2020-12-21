import math
import os
import queue
import threading
from datetime import datetime

from evtx import PyEvtxParser

from evtxtools.WindowsEvent import WindowsEvent


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