from evtxtools.LogonType import LogonType


class EventDescriptor:
    def __init__(self, type: LogonType, **kwargs):
        self.__type = type
        self.__properties = dict()
        self.__properties['logon_type'] = kwargs.get('logon_type')
        self.__properties['workstation_name'] = kwargs.get('workstation_name')
        self.__properties['target_user_name'] = kwargs.get('target_user_name')
        self.__properties['target_user_sid'] = kwargs.get('target_user_sid')
        self.__properties['target_logon_id'] = kwargs.get('target_logon_id')
        self.__properties['ip_address'] = kwargs.get('ip_address')
        self.__properties['description'] = kwargs.get('description')
        self.__values = dict()

    def instantiate(self, event_data: dict):
        instance = EventDescriptor(self.type,**self.__properties)
        for property, event_entry in self.__properties.items():
            instance.__values[property] = event_data.get(event_entry)
        return instance

    @property
    def values(self):
        return self.__values

    @property
    def type(self) -> LogonType:
        return self.__type

    @property
    def description(self) -> str:
        return self.__properties.get('description')

    @property
    def logon_type(self):
        return self.__values['logon_type']

    @property
    def workstation_name(self) -> str:
        return self.__values['workstation_name']

    @property
    def target_user_name(self) -> str:
        return self.__values['target_user_name']

    @property
    def target_user_sid(self) -> str:
        return self.__values['target_user_sid']

    @property
    def target_logon_id(self) -> str:
        return self.__values['target_logon_id']

    @property
    def ip_address(self) -> str:
        return self.__values['ip_address']

EVENT_DESCRIPTORS = {
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
    4624: EventDescriptor(type=LogonType.LOGIN_SUCCESS,
                          logon_type='LogonType',
                          workstation_name='WorkstationName',
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId',
                          ip_address='IpAddress'),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
    4625: EventDescriptor(type=LogonType.LOGIN_FAILURE,
                          description='An account failed to log on',
                          logon_type='LogonType',
                          workstation_name='WorkstationName',
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId',
                          ip_address='IpAddress'),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634
    4634: EventDescriptor(type=LogonType.LOGOUT,
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId'),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4647
    4647: EventDescriptor(type=LogonType.LOGOUT,
                          target_user_name='TargetUserName',
                          target_user_sid='TargetUserSid',
                          target_logon_id='TargetLogonId'),

    131:  EventDescriptor(type=LogonType.RDP_ACCEPTED_CONNECTION,
                          description='Accepted RDP connection',
                          workstation_name='ClientIP'
                          ),
    103:  EventDescriptor(type=LogonType.RDP_CLOSED_CONNECTION,
                          description='Closed RDP connection'
                          ),

    140:  EventDescriptor(type=LogonType.RDP_FAILURE,
                          description='RDP connection failed',
                          workstation_name='IPString'
                          ),

    192:    EventDescriptor(type=LogonType.WINRM_FAILURE,
                            description='WinRM authentication failure'
                            )
}