"""
evtx2sqlite.py

converts evtx files to a sqlite database.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""
from datetime import datetime
from pathlib import Path

import progressbar
from evtx import PyEvtxParser
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

import evtxtools
import orjson
import db


class Memoize:
    def __init__(self, fn):
        self.fn = fn
        self.memo = dict()

    def __call__(self, session: Session, clazz, filter:dict, **kwargs):
        if clazz not in self.memo:
            mc = self.memo[clazz] = dict()
        else:
            mc = self.memo[clazz]

        s_filter = str(filter)
        if s_filter not in mc:
            mc[s_filter] = self.fn(session=session, clazz=clazz, filter=filter, **kwargs)
        return mc[s_filter]


def db_create(db_file: Path) -> Engine:
    engine = create_engine('sqlite:///{file}'.format(file=db_file.name), echo=False)
    #engine = create_engine('sqlite:///:memory:', echo=False)

    db.Base.metadata.create_all(engine)

    return engine


@Memoize
def store_item(session: Session, clazz, filter:dict, **kwargs) -> int:
    result = session.query(clazz).filter_by(**filter).with_entities(clazz.id).all()
    if len(result) == 0:
        kwargs['id'] = db.id()
        session.execute(clazz.__table__.insert(), kwargs)
        return kwargs['id']
    else:
        return result[0]


def store_event(session, record:dict):
    if record['timestamp'][19] == '.':
        timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S.%f %Z")
    else:
        timestamp = datetime.strptime(record['timestamp'], "%Y-%m-%d %H:%M:%S %Z")

    record_data = orjson.loads(record['data'])
    rd_event = record_data['Event']
    rd_system = rd_event['System']

    execution_id = None
    provider_id = None
    correlation_id = None
    channel_id = None
    computer_id = None

    if 'Execution' in rd_system:
        rd_execution = rd_system['Execution']['#attributes']
        process_id = int(rd_execution['ProcessID'])
        thread_id = int(rd_execution['ThreadID'])
        execution_id = store_item(  session,
                                    clazz=db.Execution,
                                    filter={"process_id": process_id, "thread_id": thread_id},
                                    process_id=process_id,
                                    thread_id=thread_id)
    if 'Provider' in rd_system:
        rd_provider = rd_system['Provider']['#attributes']
        name = rd_provider['Name']
        guid = rd_provider.get('Guid')
        provider_id = store_item(   session,
                                    clazz=db.Provider,
                                    filter={"name": name},
                                    name=name,
                                    guid=guid)
    if 'Correlation' in rd_system:
        rd_correlation = rd_system['Correlation']
        if rd_correlation:
            rd_correlation = rd_correlation['#attributes']
            activityid = rd_correlation['ActivityID']
            relatedactivityid = rd_correlation.get('RelatedActivityID')
            channel_id = store_item(    session,
                                        clazz=db.Correlation,
                                        filter={"activityid": activityid},
                                        activityid=activityid,
                                        relatedactivityid=relatedactivityid)
    if 'Channel' in rd_system:
        channel_id = store_item(    session,
                                    clazz=db.Channel,
                                    filter={"name": rd_system['Channel']},
                                    name=rd_system['Channel'])
    if 'Computer' in rd_system:
        computer_id = store_item(session,
                                clazz=db.Computer,
                                filter={"name": rd_system['Computer']},
                                name=rd_system['Computer'])

    if isinstance(rd_system['EventID'], dict):
        event_id = int(rd_system['EventID']['#text'])
    else:
        event_id = int(rd_system['EventID'])

    event = {
        'id':db.id(),
        'event_id' : event_id,
        'timecreated' :  timestamp,
        'provider_id' : provider_id,
        'recordid' : int(rd_system['EventRecordID']),
        'execution_id' : execution_id,
        'correlation_id' : correlation_id,
        'channel_id' : channel_id,
        'computer_id' : computer_id
    }
    session.execute(db.Event.__table__.insert(), event)

    batch=list()
    if 'EventData' in rd_event and isinstance(rd_event['EventData'], dict):
        for key,value in rd_event['EventData'].items():
            if key == '#attributes':
                continue
            if key == 'Binary':
                continue
            if isinstance(value, dict) and '#text' in value:
                value = value['#text']
            elif isinstance(value, list):
                value = ', '.join(value)
            if value:
                batch.append({'id':db.id(), 'eventid':event['id'], 'key':key, 'value':value})
        if len(batch) > 0:
            session.execute(db.EventData.__table__.insert(),batch)
    session.commit()

def evtx2sqlite(evtx_files: set, db_file: Path):
    engine = db_create(db_file)
    Session = sessionmaker(bind=engine)
    session = Session()

    for f in evtx_files:
        parser = PyEvtxParser(str(f))
        for e in progressbar.progressbar(parser.records_json(), prefix=f.name):
            store_event(session, e)
        #return



def main():
    args = evtxtools.parse_evtx2sqlite_arguments()

    evtx_files = set()
    for f in args.logsdir.iterdir():
        if f.name.endswith(".evtx"):
            evtx_files.add(f)
    evtx2sqlite(evtx_files, args.dbfile)


if __name__ == '__main__':
    main()
