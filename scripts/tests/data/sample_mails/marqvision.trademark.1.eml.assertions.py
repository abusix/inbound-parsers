from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    urls = [
        'https://www.overvoltbattery.it/prodotto/lg-m50l-21700/',
        'https://www.overvoltbattery.it/prodotto/lg-m58t/',
        'https://www.overvoltbattery.it/prodotto/lg-mj1-18650/',
    ]
    assert len(events) == 3
    for i in range(3):
        assert events[i].url == urls[i]
