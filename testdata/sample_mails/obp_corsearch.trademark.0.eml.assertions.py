from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert (
        event.url
        == 'https://www.hobbybox.fi/eco-body-pump-setti-20kg?gad_source=1&gclid=Cj0KCQjwk6SwBhDPARIsAJ59GwdhVaNOg0A_UjcMJ-rANfmlPP6mcJO_x6Gx0l9D933DnvRgsDWx17gaAiHeEALw_wcB'  # noqa: E501
    )
