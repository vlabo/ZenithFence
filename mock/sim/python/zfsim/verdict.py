"""The verdicts an agent sends (driver/src/connection.rs)."""
import enum


class Verdict(enum.IntEnum):
    UNDECIDED = 0
    UNDETERMINABLE = 1
    ACCEPT = 2
    PERMANENT_ACCEPT = 3
    BLOCK = 4
    PERMANENT_BLOCK = 5
    DROP = 6
    PERMANENT_DROP = 7
    REDIRECT_NAME_SERVER = 8
    REDIRECT_TUNNEL = 9
    FAILED = 10
