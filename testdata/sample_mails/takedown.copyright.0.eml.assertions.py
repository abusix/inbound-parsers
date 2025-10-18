from typing import List

from ahq_events.event.event import Event
from ahq_parser_processors.processors import magic_datetime_parser


def assertions(events: List[Event]):
    assert len(events) == 1
    event = events[0]
    assert event.url == 'https://www.javmag.net/video/111121_01&lang=zh-CN'
    assert event.event_types[0].__getattribute__('copyright_owner') == 'Dreamroom Productions, Inc'
    assert event.event_types[0].__getattribute__('official_url') == 'https://www.10musume.com'
    assert event.event_date == magic_datetime_parser('Wed, 13 Nov 2024 22:32:09 +0000')
