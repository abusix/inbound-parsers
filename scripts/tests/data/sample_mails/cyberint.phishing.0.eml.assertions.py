from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert (
        event.url
        == 'https://www.domoprogetti.it/site/9/_request?_session=CE598C$emYM$iF3uPaFPdXNoc3ByaW5AeWFob28uY29t83Js6Ts1V7z1G9DhicBewACcX1H5B4S6HDkDmE1k3KUj-&afn=422&afnq=5'  # noqa: E501
    )
