from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip == IPv4Address('85.4.103.8')
    assert event.url == 'https://eltha.wtf/FNCwdlVM'
