from datetime import datetime
from elasticsearch_dsl import Document, Date, Nested, Boolean, \
    analyzer, InnerDoc, Completion, Keyword, Text, Integer

class WindowsEvent(Document):
    event = Nested(
        properties={
            'code': Integer(),
            'created': Date(),
            'provider': Keyword(),
            'level': Integer()
        }
    )
    record_id = Integer()
    level = Integer()
    timestamp = Date()
    correlation = Nested(
        properties={
            'activity_id': Text(),
            'related_activity_id': Text()
        }
    )
    activity_id = Text()
    execution = Nested(
        properties={
            'process_id': Integer(),
            'thread_id': Integer()
        }
    )
    channel = Keyword()
    computer = Keyword()
    user = Nested(
        properties={
            'id': Keyword()
        }
    )
    event_data = Nested()
    log = Nested(
        properties={
            'file': Nested(
                properties={
                    'path': Keyword()
                }
            ),
            'level': Integer()
        }
    )
    json = Text()
