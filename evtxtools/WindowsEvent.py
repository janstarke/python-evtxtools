import xml
from datetime import datetime

import orjson

from evtxtools.EventDescriptor import EVENT_DESCRIPTORS, EventDescriptor
from evtxtools.LogSource import LogSource

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
        timestamp = record['timestamp']
        if timestamp[19] == '.':
            self.__timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S.%f %Z")
        else:
            self.__timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S %Z")


        if from_date and self.__timestamp < from_date:
            raise WindowsEvent.IgnoreThisEvent()

        if to_date and self.__timestamp > to_date:
            raise WindowsEvent.IgnoreThisEvent()

        record_data = orjson.loads(record['data'])

        self.__event_id = record_data['Event']['System']['EventID']
        if isinstance(self.__event_id, dict):
            self.__event_id = self.__event_id['#text']
        self.__event_id = int(self.__event_id)

        if self.__event_id not in included_event_ids:
            raise WindowsEvent.IgnoreThisEvent()

        self.__descriptor = EVENT_DESCRIPTORS[self.__event_id]
        if self.__descriptor.log_source != LogSource(record_data['Event']['System']['Channel']):
            raise WindowsEvent.IgnoreThisEvent()

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

    #def __getattr__(self, item):
    #    key = self.descriptor.properties.get(item)
    #    if key is None:
    #        return None
    #
    #    return self.__event_data.get(key)

    class FriendlyDict(dict):
        def __missing__(self, key):
            return '-'

    def __str__(self):
        return self.descriptor.description.format_map(WindowsEvent.FriendlyDict(self.event_data))

    def latex_str(self):
        data = dict()
        for key, value in self.event_data.items():
            data[key] = value.replace("\\", "\\\\").replace('"', '\\"') if isinstance(value, str) else value
        res = self.descriptor.latex_description.format_map(WindowsEvent.FriendlyDict(data))
        return res.replace("%", "\\%").replace("$", "\\$")