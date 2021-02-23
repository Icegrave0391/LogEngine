from typing import List, Callable

from .beat_state import BeatState
from .logparser import LogParser

import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class ManagerBase:
    """
    Base class of managers.
    """
    # TODO(): refine some comman design patterns to the basic class
    def __init__(self, stashes:List[BeatState]):
        self.beat_stashes = stashes

    def filter_syscall(self):
        stashes = []
        for beat in self.beat_stashes:
            if beat.is_type_syscall:
                stashes.append(beat)
        return stashes

    def filter(self, filter:Callable, filter_syscall=True):
        stashes = []
        sources = self.beat_stashes
        if filter_syscall:
            sources = self.filter_syscall()
        for beat in sources:
            if filter(beat):
                stashes.append(beat)
        return stashes

    def syscall_analyzer(self, beat:BeatState):
        pass
