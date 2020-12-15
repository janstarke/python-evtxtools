import functools
import sys
import argparse
from evtx import PyEvtxParser
import xmltodict
from datetime import datetime
import progressbar

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

  def __init__(self):
    self.__login_timestamp = None
    self.__login_eventid = None
    self.__login_data = None
    self.__logout_timestamp = None
    self.__logout_eventid = None
    self.__logout_data = None

  def logout(self, timestamp: datetime, eventid: int, event_data: dict):
    self.__logout_timestamp = timestamp
    self.__logout_eventid = eventid
    self.__logout_data = event_data

  def login(self, timestamp: datetime, eventid: int, event_data: dict):
    self.__login_timestamp = timestamp
    self.__login_eventid = eventid
    self.__login_data = event_data

  @property
  def logged_out(self) -> bool:
    return (self.__logout_timestamp is not None)

  @property
  def logged_in(self) -> bool:
    return (self.__login_timestamp is not None)

  def __str__(self):
    if self.logged_in and self.logged_out:
      return "%s - %s: %s login as %s from %s (%s)" % (
        self.__login_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        self.__logout_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        self.LOGON_TYPES[int(self.__login_data['LogonType'])],
        self.__login_data['TargetUserName'],
        self.__login_data['WorkstationName'],
        self.__login_data['IpAddress']
      )
    elif self.logged_in and not self.logged_out:
      return "%s - %s: %s login as %s from %s (%s)" % (
        self.__login_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "????-??-?? ??:??:??",
        self.LOGON_TYPES[int(self.__login_data['LogonType'])],
        self.__login_data['TargetUserName'],
        self.__login_data['WorkstationName'],
        self.__login_data['IpAddress']
      )
    elif not self.logged_in and self.logged_out:
      if 'WorkstationName' in self.__logout_data:
        workstation = self.__logout_data['WorkstationName']
      else:
        workstation = "-"
      return "%s - %s: %s login as %s from %s" % (
        "????-??-?? ??:??:??",
        self.__logout_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "Unknown",
        self.__logout_data['TargetUserName'],
        workstation
      )
    else:
      return "Invalid data"

  def merge(self, new_event, attribute):
    if self.__login_data[attribute] == '-':
      self.__login_data[attribute] = new_event[attribute]

  @property
  def login_data(self):
    return self.__login_data

  @property
  def login_timestamp(self):
    return self.__login_timestamp

  @property
  def logout_timestamp(self):
    return self.__logout_timestamp

  @property
  def session_id(self):
    return self.__login_data['TargetLogonId']

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

  def __ne__(self, other):
    if self.logged_in != other.logged_in:
      return True
    if self.logged_out != other.logged_out:
      return True
    if self.logged_in:
      return self.login_timestamp.__ne__(other.login_timestamp)
    elif self.logged_out:
      return self.logout_timestamp.__ne__(other.logout_timestamp)
    else:
      return False

  def __lt__(self, other):
    if self.logged_in == other.logged_in:
      if self.logged_in:
        return self.login_timestamp.__lt__(other.login_timestamp)
      elif self.logged_out:
        return self.logout_timestamp.__lt__(other.logout_timestamp)
      else:
        return False
    else:
      if other.logged_out:
        return other.logout_timestamp.__lt__(self.__login_timestamp)
      elif other.logged_in:
        return other.login_timestamp.__gt__(self.__logout_timestamp)

def handle_record(record, sessions: dict):
  raw_data = record['data']
  idx = raw_data.find('\n')
  xml = xmltodict.parse(raw_data[idx:])

  event_id = int(xml['Event']['System']['EventID'])
  if event_id not in [4624, 4634, 4647]:
    return

  timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S.%f UTC")

  event_data = dict()
  for d in xml['Event']['EventData']['Data']:
    event_data[d['@Name']] = d['#text']

  if event_data['TargetUserSid'] in [
      'S-1-5-18',   # local system
      'S-1-5-7',    # anonymous
      'S-1-5-90-1', # DWM-1
      'S-1-5-90-4'  # DWM-4
    ]:
    return
  if event_id == 4624:
    if event_data['TargetLogonId'] in sessions.keys():
      # merge both entries
      e = sessions[event_data['TargetLogonId']]
      if e.logged_in:
        e.merge(event_data, 'WorkstationName')
        e.merge(event_data, 'IpAddress')
        e.merge(event_data, 'TargetUserName')
        e.merge(event_data, 'TargetUserSid')
      else:
        e.login(timestamp, event_id, event_data)
    else:
      session = LoginSession()
      session.login(timestamp, event_id, event_data)
      sessions[event_data['TargetLogonId']] = session
  elif event_id in [4634, 4647]:
    logon_id = None
    if 'TargetLogonId' in event_data.keys():
      logon_id = event_data['TargetLogonId']
    elif 'SubjectLogonId' in event_data.keys():
      logon_id = event_data['SubjectLogonId']

    if logon_id not in sessions.keys():
      session = LoginSession()
      session.logout(timestamp, event_id, event_data)
      sessions[logon_id] = session
    else:
      session = sessions[event_data['TargetLogonId']]
      session.logout(timestamp, event_id, event_data)

  assert sessions[event_data['TargetLogonId']] is not None


def print_logins(secfile, from_date, to_date):
  parser = PyEvtxParser(secfile)

  if from_date:
    from_date = datetime.strptime(from_date, "%Y-%m-%d %H:%M:%S UTC")
  else:
    from_date = datetime.min

  if to_date:
    to_date = datetime.strptime(to_date, "%Y-%m-%d %H:%M:%S UTC")
  else:
    to_date = datetime.max

  assert from_date <= to_date

  sessions = dict()
  for record in progressbar.progressbar(parser.records()):
    timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S.%f UTC")
    if timestamp < from_date or timestamp > to_date:
      continue

    handle_record(record, sessions)

  for s in sorted(sessions.values()):
    print(str(s))

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='analyse user sessions')
  parser.add_argument('--evtx',
                      dest='secfile',
                      help='path of the Security.evtx file (default: stdin)',
                      type=argparse.FileType('rb'))

  parser.add_argument('--from',
                      dest='from_date',
                      help='timestamp pattern, where to start',
                      type=str)

  parser.add_argument('--to',
                      dest='to_date',
                      help='timestamp pattern, where to end',
                      type=str)

  args = parser.parse_args()
  secfile = args.secfile or sys.stdin

  print_logins(secfile, args.from_date, args.to_date)