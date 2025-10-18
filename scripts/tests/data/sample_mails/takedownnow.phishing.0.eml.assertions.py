from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip == IPv4Address('23.227.32.0')
    assert event.url == 'https://promo.shoptaiff.com/'
