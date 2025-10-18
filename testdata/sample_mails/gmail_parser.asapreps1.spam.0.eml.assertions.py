from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event
from ahq_parser_processors.processors import magic_datetime_parser


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.url == 'ekzamen-rus.ru'
    assert event.ip == IPv4Address('185.155.184.33')
    assert event.event_date == magic_datetime_parser('Tue, 16 Jul 2024 14:30:58 -0500')
