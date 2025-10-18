from ipaddress import IPv4Address
from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 14
    ips = [
        '117.103.124.146',
        '117.103.124.147',
        '119.31.167.19',
        '119.31.168.215',
        '209.212.229.132',
        '209.212.229.133',
        '209.212.229.57',
        '209.212.229.59',
        '209.212.232.132',
        '209.212.232.133',
        '209.212.232.194',
        '46.235.109.54',
        '64.254.120.52',
        '64.254.120.53',
    ]
    for i in range(14):
        event = events[i]
        assert event.ip == IPv4Address(ips[i])
