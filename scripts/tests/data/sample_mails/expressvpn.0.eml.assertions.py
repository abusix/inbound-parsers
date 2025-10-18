from ipaddress import IPv4Address, IPv6Address
from typing import List

from ahq_events.event.event import Event

ACCEPTIABLE_IPs = [
    IPv4Address('1.1.1.1'),
    IPv4Address('1.0.0.1'),
    IPv6Address('2606:4700:4700::1111'),
    IPv6Address('2606:4700:4700::1001'),
]


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.ip in ACCEPTIABLE_IPs
    assert event.url == 'https://one.one.one.one/hello-world/I-am-a-specially-crafted-url-for-tests'
