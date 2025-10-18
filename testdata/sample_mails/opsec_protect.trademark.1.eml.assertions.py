from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert (
        event.url
        == 'https://www.ciravision.in/?c=ci-253-1861063-philippe-charriol-bracelet-replica'
    )
    assert event.ip == IPv4Address('191.101.104.164')
