from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert (
        event.url
        == 'http://www.yangondirectory.com/listing/petro-canada-auto-coment-co-ltd-l00305351.html'
    )
