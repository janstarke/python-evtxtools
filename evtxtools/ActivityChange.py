from enum import unique, auto, Enum


@unique
class ActivityChange(Enum):
    START_ACTIVITY = auto()
    END_ACTIVITY = auto()
    NO_ACTIVITY = auto()
    NO_CHANGE = auto()