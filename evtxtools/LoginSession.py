import functools
from datetime import datetime, timedelta

from evtxtools.EventDescriptor import EventDescriptor
from evtxtools.LogonType import LogonType


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
    UNKNOWN_TIME = "????-??-?? ??:??:??"
    NO_TIME      = "                   "

    def __init__(self, event_id: int, timestamp: datetime, event: EventDescriptor):
        self.__login_timestamp = None
        self.__login_event_id = None
        self.__login_event = None
        self.__logout_timestamp = None
        self.__logout_event_id = None
        self.__logout_event = None
        self.__description = event.description
        self.__can_logout = True

        if event.type in [LogonType.LOGIN_SUCCESS, LogonType.RDP_ACCEPTED_CONNECTION]:
            self.__login_event_id = event_id
            self.__login_timestamp = timestamp
            self.__login_event = event
        elif event.type in [LogonType.LOGOUT, LogonType.RDP_CLOSED_CONNECTION]:
            self.__logout_event_id = event_id
            self.__logout_timestamp = timestamp
            self.__logout_event = event
        else:
            self.__login_event_id = event_id
            self.__login_timestamp = timestamp
            self.__login_event = event
            self.__can_logout = False

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
        if self.__can_logout:
            return "%s - %s (%s): %s login as %s from %s (%s)" % (
                self.login_time,
                self.logout_time,
                self.duration,
                self.login_type,
                self.username,
                self.workstation_name,
                self.ip_address
            )
        else:
            return "%s: %s as %s from %s (%s)" % (
                self.login_time,
                self.__description,
                self.username,
                self.workstation_name,
                self.ip_address
            )

    @property
    def duration(self) -> timedelta:
        if self.__login_timestamp and self.__logout_timestamp:
            return self.__logout_timestamp - self.__login_timestamp
        else:
            return ""

    @property
    def login_time(self):
        return self.__login_timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.__login_timestamp else self.UNKNOWN_TIME

    @property
    def logout_time(self):
        return self.__logout_timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.__logout_timestamp else self.UNKNOWN_TIME

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
                return self.login_timestamp < other.login_timestamp
            elif self.logged_out:
                return self.logout_timestamp < other.logout_timestamp
            else:
                return False
        else:
            if other.logged_out:
                if self.logged_in:
                    return other.logout_timestamp < self.__login_timestamp
                else:
                    return True
            elif other.logged_in:
                if self.logged_out:
                    return other.login_timestamp > self.__logout_timestamp
                else:
                    return True