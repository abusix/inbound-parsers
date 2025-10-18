from typing import List

from ahq_events.event.event import Event
from ahq_parser_processors.processors import magic_datetime_parser


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.url == 'https://www.godaddy.com/whois/results.aspx?domain=romancejunction.info'
    assert event.event_date == magic_datetime_parser('Fri, 10 May 2024 10:56:33 -0400')
