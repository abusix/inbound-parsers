from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip == IPv4Address('89.46.109.24')
    assert (
        event.url
        == 'https://www.olmarzonzini.com/it/detail/6/profumi-di-nicchia/14359/escentric-molecules-molecule-01-edt-100ml-spray-inscatolato'  # noqa: E501
    )
