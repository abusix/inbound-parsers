import datetime
from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip == IPv4Address('129.232.155.150')
    assert event.event_date == datetime.datetime.strptime(
        'Sat, Feb 17, 2024 at 1:42 AM', '%a, %b %d, %Y at %I:%M %p'
    )
