import functools
from datetime import datetime, timedelta

from evtxtools.ActivityChange import ActivityChange
from evtxtools.EventDescriptor import EventDescriptor
from evtxtools.LogonType import EventType
from evtxtools.WindowsEvent import WindowsEvent


@functools.total_ordering
class Activity:
    UNKNOWN_TIME = "????-??-?? ??:??:??"
    NO_TIME      = "                   "

    def __init__(self):
        self.__begin_event = None
        self.__end_event = None
        self.__events = dict()
        self.__activity_id = None

    def add_event(self, event: WindowsEvent):
        self.__events[event.timestamp] = event
        if self.__activity_id is None:
            self.__activity_id = event.activity_id
        else:
            assert self.__activity_id == event.activity_id

        if event.descriptor.activity_change == ActivityChange.START_ACTIVITY:
            if self.__begin_event is None or event.timestamp < self.__begin_event.timestamp:
                self.__begin_event = event
        elif event.descriptor.activity_change == ActivityChange.END_ACTIVITY:
            if self.__end_event is None or event.timestamp > self.__end_event.timestamp:
                self.__end_event = event

    @property
    def logged_out(self) -> bool:
        return self.__begin_timestamp is not None

    @property
    def logged_in(self) -> bool:
        return self.__end_timestamp is not None

    def __str__(self):
        if len(self.__events) == 1:
            event = next(iter(self.__events.values()))
            return "%s: %s" % (
                event.timestamp,
                str(event)
            )

        timestamps = list(sorted(self.__events.keys()))
        first_event = self.__begin_event or self.__events[timestamps[0]]
        last_event = self.__end_event or self.__events[timestamps[-1]]
        return "%s - %s (%s): %s" % (
            first_event.timestamp,
            last_event.timestamp,
            last_event.timestamp - first_event.timestamp,
            str(first_event)
        )

    @property
    def login_time(self):
        return self.__end_timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.__end_timestamp else self.UNKNOWN_TIME

    @property
    def logout_time(self):
        return self.__begin_timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.__begin_timestamp else self.UNKNOWN_TIME

    @property
    def username(self):
        if self.__begin_event:
            if self.__begin_event.target_user_name:
                return self.__begin_event.target_user_name
        if self.__end_event:
            if self.__end_event.target_user_name:
                return self.__end_event.target_user_name
        return "unknown user"

    @property
    def workstation_name(self):
        if self.__begin_event:
            if self.__begin_event.workstation_name:
                return self.__begin_event.workstation_name
        return '-'

    @property
    def ip_address(self):
        if self.__begin_event:
            if self.__begin_event.ip_address:
                return self.__begin_event.ip_address
        return '-'

    @property
    def login_timestamp(self):
        return self.__end_timestamp

    @property
    def logout_timestamp(self):
        return self.__begin_timestamp

    @property
    def activity_id(self):
        return self.__activity_id

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
        assert len(self.__events) > 0
        assert len(other.__events) > 0
        my_first_event = self.__events[sorted(self.__events.keys())[0]]
        your_first_event = other.__events[sorted(other.__events.keys())[-1]]
        return my_first_event.timestamp < your_first_event.timestamp