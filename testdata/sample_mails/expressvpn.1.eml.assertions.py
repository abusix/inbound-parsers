from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert not event.ip
    assert isinstance(event.error, str)
    assert (
        event.url
        == 'https://this-domain-does-not-exist-ever-to-a-100-percent.co.uk/and-i-am-specially-crafted-for-a-test'  # noqa: E501
    )
