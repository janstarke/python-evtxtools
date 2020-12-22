from evtxtools.LogonType import EventType
from evtxtools.ActivityChange import ActivityChange


class EventDescriptor:
    def __init__(self, type: EventType, activity_change: ActivityChange, **kwargs):
        self.__type = type
        self.__activity_change = activity_change
        self.__properties = dict()
        self.__properties['logon_type'] = kwargs.get('logon_type')
        self.__properties['workstation_name'] = kwargs.get('workstation_name')
        self.__properties['target_user_name'] = kwargs.get('target_user_name')
        self.__properties['target_user_sid'] = kwargs.get('target_user_sid')
        self.__properties['target_logon_id'] = kwargs.get('target_logon_id')
        self.__properties['ip_address'] = kwargs.get('ip_address')
        self.__properties['description'] = kwargs.get('description')
        assert self.__properties['description'] is not None
        self.__values = dict()

    def instantiate(self, event_data: dict):
        instance = EventDescriptor(self.type, self.__activity_change, **self.__properties)
        for property, event_entry in self.__properties.items():
            instance.__values[property] = event_data.get(event_entry)
        return instance

    @property
    def properties(self):
        return self.__properties

    @property
    def values(self):
        return self.__values

    @property
    def type(self) -> EventType:
        return self.__type

    @property
    def activity_change(self) -> ActivityChange:
        return self.__activity_change

    @property
    def description(self) -> str:
        return self.__properties.get('description')

    @property
    def logon_type(self):
        return self.__values.get('logon_type')

    @property
    def workstation_name(self) -> str:
        return self.__values.get('workstation_name')

    @property
    def target_user_name(self) -> str:
        return self.__values.get('target_user_name')

    @property
    def target_user_sid(self) -> str:
        return self.__values.get('target_user_sid')

    @property
    def target_logon_id(self) -> str:
        return self.__values.get('target_logon_id')

    @property
    def ip_address(self) -> str:
        return self.__values.get('ip_address')

EVENT_DESCRIPTORS = {
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
    4624: EventDescriptor(type=EventType.LOGIN_SUCCESS,
                          activity_change=ActivityChange.START_ACTIVITY,
                          description="{LogonType} login as {TargetUserName} from {WorkstationName} ({IpAddress})",
                          ),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
    4625: EventDescriptor(type=EventType.LOGIN_FAILURE,
                          activity_change=ActivityChange.NO_ACTIVITY,
                          description='Account {TargetUserName} failed to log on from {WorkstationName} ({IpAddress})',
                          ),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634
    4634: EventDescriptor(type=EventType.LOGOUT,
                          description="An account was logged off.",
                          activity_change=ActivityChange.END_ACTIVITY,
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId'),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4647
    4647: EventDescriptor(type=EventType.LOGOUT,
                          description="User initiated logoff.",
                          activity_change=ActivityChange.END_ACTIVITY,
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId'),

    131:  EventDescriptor(type=EventType.RDP_ACCEPTED_CONNECTION,
                          description='Accepted RDP connection from {ClientIP}',
                          activity_change=ActivityChange.START_ACTIVITY
                          ),
    103:  EventDescriptor(type=EventType.RDP_CLOSED_CONNECTION,
                          activity_change=ActivityChange.END_ACTIVITY,
                          description='Closed RDP connection'
                          ),

    140:  EventDescriptor(type=EventType.RDP_FAILURE,
                          activity_change=ActivityChange.NO_ACTIVITY,
                          description='RDP connection from {IPString} failed'
                          ),

    192:    EventDescriptor(type=EventType.WINRM_FAILURE,
                            activity_change=ActivityChange.NO_ACTIVITY,
                            description='WinRM authentication failure'
                            )
}