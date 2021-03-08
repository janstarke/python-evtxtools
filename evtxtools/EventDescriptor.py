from evtxtools.LogSource import LogSource
from evtxtools.LogonType import EventType
from evtxtools.ActivityChange import ActivityChange


def escape_lstinline(s: str):
    return s.replace("\\", "\\\\")

class EventDescriptor:
    def __init__(self, activity_change: ActivityChange, log_source:LogSource, description:str, latex_description=None):
        self.__activity_change = activity_change
        self.__log_source = log_source
        self.__description = description
        assert self.__description is not None
        self.__latex_description = latex_description

    @property
    def activity_change(self) -> ActivityChange:
        return self.__activity_change

    @property
    def description(self) -> str:
        return self.__description

    @property
    def latex_description(self):
        return self.__latex_description or self.__description

    @property
    def log_source(self):
        return self.__log_source


EVENT_DESCRIPTORS = {
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
    4624: EventDescriptor(
                          activity_change=ActivityChange.START_ACTIVITY,
                          log_source=LogSource.Security,
                          description="{LogonType} login as {TargetUserName} from {WorkstationName} ({IpAddress})",
                          latex_description="{LogonType} login as \\username{{{TargetUserName}}} "
                                            "from \\host{{{WorkstationName}}} (\\host{{{IpAddress}}})",
                          ),

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
    4625: EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                          log_source=LogSource.Security,
                          description='Account {TargetUserName} failed to log on from {WorkstationName} ({IpAddress})',
                          latex_description='Account \\username{{{TargetUserName}}} failed to log on from \\host{{{WorkstationName}}} (\\host{{{IpAddress}}})',
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
                            latex_description="\\username{{{SubjectUserName}}} attempted to run \\lstinline!{ProcessName}! as \\username{{{TargetUserName}}}",
                          log_source=LogSource.Security,
                          activity_change=ActivityChange.NO_ACTIVITY),

    7045: EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                          log_source=LogSource.System,
                          description="New service {ServiceName} installed as {ImagePath}, "
                                      "ServiceType={ServiceType}, StartType={StartType}",
                          latex_description="New service \\lstinline!{ServiceName}! installed as \\lstinline!{ImagePath}!, "
                                      "ServiceType=\\lstinline!{ServiceType}!, StartType=\\lstinline!{StartType}!"
                          ),
    131:  EventDescriptor(description='Accepted RDP connection from {ClientIP}',
                            latex_description='Accepted RDP connection from \\host{{{ClientIP}}}',
                          log_source=LogSource.Microsoft_Windows_RemoteDesktopServices_RdpCoreTS_Operational,
                          activity_change=ActivityChange.START_ACTIVITY
                          ),
    103:  EventDescriptor(activity_change=ActivityChange.END_ACTIVITY,
                          log_source=LogSource.Microsoft_Windows_RemoteDesktopServices_RdpCoreTS_Operational,
                          description='Closed RDP connection'
                          ),

    140:  EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                          log_source=LogSource.Microsoft_Windows_RemoteDesktopServices_RdpCoreTS_Operational,
                          description='RDP connection from {IPString} failed',
                          latex_description='RDP connection from \\host{{{IPString}}} failed'
                          ),

    192:    EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                            log_source=LogSource.Microsoft_Windows_RemoteDesktopServices_RdpCoreTS_Operational,
                            description='WinRM authentication failure'
                            ),

    400:    EventDescriptor(activity_change=ActivityChange.START_ACTIVITY,
                            log_source=LogSource.Windows_PowerShell,
                            description="Started PowerShell command: {HostApplication}",
                            latex_description="Started PowerShell command: \\lstinline!{HostApplication}!"),
    403:    EventDescriptor(activity_change=ActivityChange.END_ACTIVITY,
                            log_source=LogSource.Windows_PowerShell,
                            description="End of PowerShell command"),

    551:    EventDescriptor(activity_change=ActivityChange.NO_ACTIVITY,
                            log_source=LogSource.Microsoft_Windows_SmbServer_Security,
                            description="SMB authentication by {ClientName} failed")
}