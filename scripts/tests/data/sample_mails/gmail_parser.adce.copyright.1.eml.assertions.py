from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip == IPv4Address('167.99.200.7')
    assert event.url == 'http://front-tuga-3.gestao-vip.xyz/.../161034.ts?token=...'
