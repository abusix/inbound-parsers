from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip == IPv4Address('139.162.142.145')
    assert event.url == 'http://front-tug-6.cdn007.xyz/.../6422?token=....'
