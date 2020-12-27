import sys

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

Base = declarative_base()


def __id():
    num = 0
    while True:
        yield num
        num += 1


__id_val = __id()


def id():
    return next(__id_val)


class Provider(Base):
    __tablename__ = 'provider'
    id = Column(Integer, primary_key=True)
    name = Column(Text, unique=True)
    guid = Column(Text)

    def __repr__(self):
        return self.name


class Correlation(Base):
    __tablename__ = 'correlation'
    id = Column(Integer, unique=True, nullable=False, primary_key=True)
    activityid = Column(Text, unique=True)
    relatedactivityid = Column(Text, unique=True)

    def __repr__(self):
        return self.activityid


class Execution(Base):
    __tablename__ = 'execution'
    id = Column(Integer, unique=True, nullable=False, primary_key=True)
    process_id = Column(Integer, nullable=False)
    thread_id = Column(Integer, nullable=False)
    __table_args__ = (
        UniqueConstraint('process_id', 'thread_id', name="unique_thread"),
    )


class Channel(Base):
    __tablename__ = 'channel'
    id = Column(Integer, unique=True, nullable=False, primary_key=True)
    name = Column(Text, unique=True)

    def __repr__(self):
        return self.name


class Computer(Base):
    __tablename__ = 'computer'
    id = Column(Integer, unique=True, nullable=False, primary_key=True)
    name = Column(Text, unique=True)

    def __repr__(self):
        return self.name


class Event(Base):
    __tablename__ = 'event'
    id = Column(Integer, unique=True, nullable=False, primary_key=True)
    event_id = Column(Integer, nullable=False)
    provider_id = Column(Integer, ForeignKey("provider.id"), nullable=False)
    timecreated = Column(DateTime, nullable=False)
    recordid = Column(Integer)
    correlation_id = Column(Integer, ForeignKey("correlation.id"), nullable=True)
    execution_id = Column(Integer, ForeignKey("execution.id"), nullable=True)
    channel_id = Column(Integer, ForeignKey("channel.id"), nullable=True)
    computer_id = Column(Integer, ForeignKey("computer.id"), nullable=True)
    userid = Column(Text, nullable=True)

    provider = relationship("Provider")
    execution = relationship("Execution")
    channel = relationship("Channel")
    computer = relationship("Computer")

class EventData(Base):
    __tablename__ = 'event_data'
    id = Column(Integer, unique=True, nullable=False, primary_key=True)
    eventid = Column(Integer, ForeignKey("event.id"), nullable=False)
    key = Column(Text, nullable=False)
    value = Column(Text, nullable=False)

    event = relationship("Event", back_populates="event_data")
Event.event_data = relationship("EventData", back_populates="event")