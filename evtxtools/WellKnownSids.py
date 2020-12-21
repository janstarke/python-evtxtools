from enum import Enum, unique


@unique
class WellKnownSid(Enum):
    DWM_1 = 'S-1-5-90-1'
    DWM_2 = 'S-1-5-90-2'
    DWM_3 = 'S-1-5-90-3'
    DWM_4 = 'S-1-5-90-4'

    # Users who log on to terminals using a dial-up modem. This is a group identifier.
    SECURITY_DIALUP_RID = 'S-1-5-1'

    # Users who log on across a network. This is a group identifier added to the token of a process when it was logged
    # on across a network. The corresponding logon type is LOGON32_LOGON_NETWORK.
    SECURITY_NETWORK_RID = 'S-1-5-2'

    # Users who log on using a batch queue facility. This is a group identifier added to the token of a process when it
    # was logged as a batch job. The corresponding logon type is LOGON32_LOGON_BATCH.
    SECURITY_BATCH_RID = 'S-1-5-3'

    # Users who log on for interactive operation. This is a group identifier added to the token of a process when it was
    # logged on interactively. The corresponding logon type is LOGON32_LOGON_INTERACTIVE.
    SECURITY_INTERACTIVE_RID = 'S-1-5-4'

    # Accounts authorized to log on as a service. This is a group identifier added to the token of a process when it was
    # logged as a service. The corresponding logon type is LOGON32_LOGON_SERVICE.
    SECURITY_SERVICE_RID = 'S-1-5-6'

    # Anonymous logon, or null session logon.
    SECURITY_ANONYMOUS_LOGON_RID = 'S-1-5-7'

    # Proxy.
    SECURITY_PROXY_RID = 'S-1-5-8'

    # Enterprise controllers.
    SECURITY_ENTERPRISE_CONTROLLERS_RID = 'S-1-5-9'

    # The PRINCIPAL_SELF security identifier can be used in the ACL of a user or group object. During an access check,
    # the system replaces the SID with the SID of the object. The PRINCIPAL_SELF SID is useful for specifying an
    # inheritable ACE that applies to the user or group object that inherits the ACE. It the only way of representing
    # the SID of a created object in the default security descriptor of the schema.
    SECURITY_PRINCIPAL_SELF_RID = 'S-1-5-10'

    # The authenticated users.
    SECURITY_AUTHENTICATED_USER_RID = 'S-1-5-11'

    # Restricted code.
    SECURITY_RESTRICTED_CODE_RID = 'S-1-5-12'

    # Terminal Services. Automatically added to the security token of a user who logs on to a terminal server.
    SECURITY_TERMINAL_SERVER_RID = 'S-1-5-13'

    # A special account used by the operating system.
    SECURITY_LOCAL_SYSTEM_RID = 'S-1-5-18'

    # SIDS are not unique.
    SECURITY_NT_NON_UNIQUE = 'S-1-5-21'

    # The built-in system domain.
    SECURITY_BUILTIN_DOMAIN_RID = 'S-1-5-32'

    # Write restricted code.
    SECURITY_WRITE_RESTRICTED_CODE_RID = 'S-1-5-33'

    @staticmethod
    def is_wellknown_sid(s:str) -> bool:
        if len(s) > 8:
            return False
        values = set(item.value for item in WellKnownSid)
        return s in values


class WellKnownSidFilter:
    def __init__(self):
        self.__included = set()

    def include_sid(self, sid: WellKnownSid):
        if sid not in self.__included:
            self.__included.add(sid)
        return self

    def include_local_system(self):
        self.include_sid(WellKnownSid.SECURITY_LOCAL_SYSTEM_RID)

    def include_anonymous(self):
        self.include_sid(WellKnownSid.SECURITY_ANONYMOUS_LOGON_RID)

    def is_included(self, sid: WellKnownSid) -> bool:
        return sid in self.__included

    def is_excluded(self, sid: WellKnownSid) -> bool:
        return sid not in self.__included