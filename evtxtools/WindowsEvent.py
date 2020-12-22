import xml
from datetime import datetime

import orjson

from evtxtools.EventDescriptor import EVENT_DESCRIPTORS, EventDescriptor


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


class WindowsEvent:
    class IgnoreThisEvent(Exception):
        pass

    def __init__(self, record: dict, included_event_ids: set, from_date: datetime, to_date: datetime):
        self.__timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S.%f UTC")

        if from_date and self.__timestamp < from_date:
            raise WindowsEvent.IgnoreThisEvent()

        if to_date and self.__timestamp > to_date:
            raise WindowsEvent.IgnoreThisEvent()

        try:
            record_data = orjson.loads(record['data'])
        except xml.parsers.expat.ExpatError:
            # TODO: print warning
            raise ValueError("invalid XML")

        self.__event_id = int(record_data['Event']['System']['EventID'])
        if self.__event_id not in included_event_ids:
            raise WindowsEvent.IgnoreThisEvent()

        self.__descriptor = EVENT_DESCRIPTORS[self.__event_id]


        self.__event_data = record_data['Event']['EventData']
        self.__beautify_event_data()

        try:
            self.__activity_id = self.__get_correlation_id(record_data)\
                                 or self.__timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
        except TypeError:
            pass
        except KeyError:
            pass
        except AttributeError:
            pass

    def __beautify_event_data(self):
        if 'LogonType' in self.__event_data:
            self.__event_data['LogonType'] = LOGON_TYPES[int(self.__event_data['LogonType'])]

    def __get_correlation_id(self, record_data: dict) -> str:
        try:
            activity_id = record_data['Event']['System']['Correlation']['#attributes']['ActivityID']
            if activity_id and len(activity_id) > 0:
                return activity_id
        except Exception:
            pass

        try:
            return record_data['Event']['EventData']['TargetLogonId']
        except Exception:
            pass

        return None

    @property
    def event_id(self) -> int:
        return self.__event_id

    @property
    def timestamp(self) -> datetime:
        return self.__timestamp

    @property
    def activity_id(self):
        return self.__activity_id

    @property
    def event_data(self) -> dict:
        return self.__event_data

    @property
    def descriptor(self) -> EventDescriptor:
        return self.__descriptor

    def __getattr__(self, item):
        key = self.descriptor.properties.get(item)
        if key is None:
            return None

        return self.__event_data.get(key)

    def __str__(self):
        x = self.descriptor.description.format(**self.event_data)
        return x