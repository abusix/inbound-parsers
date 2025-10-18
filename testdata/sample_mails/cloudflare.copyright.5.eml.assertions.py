from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.url == 'https://www.sotwe.com/kimseze139'
    assert event.event_types[0].__getattribute__('copyright_owner') == 'LOIHI TECHNOLOGY PTE. LTD.'
    assert event.event_types[0].__getattribute__('official_url') == 'https://likey.me/sejinming'
