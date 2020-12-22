from evtxtools.LogSource import LogSource
from evtxtools.LogonType import EventType
from evtxtools.ActivityChange import ActivityChange


class EventDescriptor:
    def __init__(self, activity_change: ActivityChange, log_source:LogSource, description:str):
        self.__activity_change = activity_change
        self.__log_source = log_source
        self.__description = description
        assert self.__description is not None

    @property
    def activity_change(self) -> ActivityChange:
        return self.__activity_change

    @property
    def description(self) -> str:
        return self.__description


EVENT_DESCRIPTORS = {
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
    4624: EventDescriptor(
                          activity_change=ActivityChange.START_ACTIVITY,
                          log_source=LogSource.Security,
                          description="{LogonType} login as {TargetUserName} from {WorkstationName} ({IpAddress})",
                          ),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
    4625: EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                          log_source=LogSource.Security,
                          description='Account {TargetUserName} failed to log on from {WorkstationName} ({IpAddress})',
                          ),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634
    4634: EventDescriptor(description="An account was logged off.",
                          activity_change=ActivityChange.END_ACTIVITY,
                          log_source=LogSource.Security),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4647
    4647: EventDescriptor(description="User initiated logoff.",
                          activity_change=ActivityChange.END_ACTIVITY,
                          log_source=LogSource.Security),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648
    4648: EventDescriptor(description="{SubjectUserName} attempted to run {ProcessName} as {TargetUserName}",
                          log_source=LogSource.Security,
                          activity_change=ActivityChange.NO_ACTIVITY),

    7045: EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                          log_source=LogSource.System,
                          description="New service {ServiceName} installed as {ImagePath}, "
                                      "ServiceType={ServiceType}, StartType={StartType}",
                          ),
    131:  EventDescriptor(description='Accepted RDP connection from {ClientIP}',
                          log_source=LogSource.Microsoft_Windows_RemoteDesktopServices_RdpCoreTS_Operational,
                          activity_change=ActivityChange.START_ACTIVITY
                          ),
    103:  EventDescriptor(activity_change=ActivityChange.END_ACTIVITY,
                          log_source=LogSource.Microsoft_Windows_RemoteDesktopServices_RdpCoreTS_Operational,
                          description='Closed RDP connection'
                          ),

    140:  EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                          log_source=LogSource.Microsoft_Windows_RemoteDesktopServices_RdpCoreTS_Operational,
                          description='RDP connection from {IPString} failed'
                          ),

    192:    EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                            log_source=LogSource.Microsoft_Windows_RemoteDesktopServices_RdpCoreTS_Operational,
                            description='WinRM authentication failure'
                            )
}