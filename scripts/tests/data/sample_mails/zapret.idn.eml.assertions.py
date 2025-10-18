from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.url == 'https://www.xn----ctbjbpl9bwc.xn--p1ai/kassovye-cheki'
