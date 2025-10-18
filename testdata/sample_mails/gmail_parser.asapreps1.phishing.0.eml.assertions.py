from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event
from ahq_parser_processors.processors import magic_datetime_parser


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip == IPv4Address('192.210.144.147')
    assert event.event_date == magic_datetime_parser('Sat, 19 Oct 2024 16:40:56 -0500')
