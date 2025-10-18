from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert (
        event.url
        == 'https://asospy.com/app/details/com.clairmail.fth/Fifth-Third%3A-53-Mobile-Banking'
    )
