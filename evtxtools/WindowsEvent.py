import xml
from datetime import datetime

import xmltodict


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
            record_data = self.__parse_record_data(record['data'])
        except xml.parsers.expat.ExpatError:
            # TODO: print warning
            raise ValueError("invalid XML")

        self.__event_id = int(record_data['Event']['System']['EventID'])

        if included_event_ids and self.__event_id not in included_event_ids:
            raise WindowsEvent.IgnoreThisEvent()

        self.__event_data = dict()

        try:
            for d in record_data['Event']['EventData']['Data']:
                if isinstance(d, dict):
                    self.__event_data[d['@Name']] = d['#text'] if '#text' in d else '-'

            self.__activity_id = self.__get_correlation_id(record_data)
        except TypeError:
            pass
        except KeyError:
            pass
        except AttributeError:
            pass

    def __get_correlation_id(self, record_data: dict) -> str:
        correlation = record_data['Event']['System'].get('Correlation')
        if correlation and '@ActivityID' in correlation:
            activity_id = record_data['Event']['System']['Correlation']['@ActivityID']
            if activity_id and len(activity_id) > 0:
                return activity_id

        data = record_data['Event']['EventData'].get('Data')
        if data:
            for d in record_data['Event']['EventData']['Data']:
                if d['@Name'] == 'TargetLogonId':
                    return d['#text']

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

    @staticmethod
    def __parse_record_data(record_data: dict) -> dict:
        idx = record_data.find('\n')
        return xmltodict.parse(record_data[idx:])