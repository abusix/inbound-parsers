from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    ips = ['90.187.52.137', '84.118.235.70', '90.187.113.105', '145.253.108.163', '95.89.187.166']
    assert len(events) == 5
    for i in range(5):
        assert events[i].ip == IPv4Address(ips[i])
