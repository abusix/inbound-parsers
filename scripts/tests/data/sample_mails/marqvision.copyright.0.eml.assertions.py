from typing import List

from ahq_events.event.event import Event


def assertions(events: List[Event]):
    assert len(events) == 1
    assert (
        events[0].url
        == 'https://brownleatherjackets.com/product/pullover-vwoollo-heart-hoodie/?attribute_size=Large&rct=j&q=&esrc=s&opi=95576897&sa=U&ved=0ahUKEwjxrvyUt6iIAxVshIkEHf8CBUMQgOUECN0P&usg=AOvVaw2LaaESiqIFrDQ6pT4pNvTd'  # noqa: E501
    )
