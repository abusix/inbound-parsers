from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.url == 'http://squest.pro/gofish?rid=ZNt4m3T'
