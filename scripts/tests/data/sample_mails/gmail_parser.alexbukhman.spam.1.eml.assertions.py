from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event
from ahq_parser_processors.processors import magic_datetime_parser


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip == IPv4Address('92.53.96.174')
    assert event.event_date == magic_datetime_parser('Thu, 19 Sep 2024 13:20:03 -0700')
