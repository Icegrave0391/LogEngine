import json
import sys
from typing import List, Optional, Dict

from .beat_state import Auditd, BeatState
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#~~~~~~~~~ .global data ~~~~~~~~#
DROPS = ['@metadata', 'service', 'agent', 'ecs', 'user']
audit_test_file = 'naive_test/auditbeat'
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

js_list = []
class LogType(enumerate):
    audit = 1,
    strace = 2

class LogParser():
    def __init__(self, type: LogType = LogType.audit,
                 lpath: str = audit_test_file,
                 outpath: Optional[str] = './log_output/res.txt'
                 ):
        self.type = type
        self.path_log = lpath
        self.path_out = outpath
        # self.events = list()
        log.info(f'Initialized a auditbeat log parser.')
        # TODO(): potentially need to support other log types(e.g. strace)

    def parse(self, output=True):
        """
        Parse the auditbeat log file, to generate audit event model
        and write to the result file(optional)

        :param output: Determine whether writing to the output file
        """
        if not self.type == LogType.audit:
            log.error("LogParser doesn't support nonetype yet.")
            return
        stashes = list()
        with open(self.path_log, 'r') as f:
            for line in f.readlines():
                event: Dict = json.loads(line)
                keys = event.keys()

                # drop irrelevant keys of dict
                for key in DROPS:
                    if key in event.keys():
                        event.pop(key)

                # retrieve json info
                timestamp, process, file = None, None, None
                if "@timestamp" in event.keys():
                    timestamp = event["@timestamp"]
                if "process" in event.keys():
                    process = event["process"]
                if "file" in event.keys():
                    file = event["file"]

                try:
                    audit:Dict = event["auditd"]
                except KeyError:
                    raise KeyError(f"line: {line} does not have audit field, parse failed.")

                # recontruct audit unit
                paths, session = None, None
                if "paths" in audit.keys():
                    paths = audit["paths"]
                if "session" in audit.keys():
                    session = audit["session"]
                try:
                    msg_type, result, sequence, data = \
                        audit["message_type"],audit["result"], audit["sequence"], audit["data"]
                except KeyError:
                    raise KeyError(f"Audit {audit} does not have certain keys, parse failed.")
                auditd = Auditd(paths, msg_type, sequence, result, data, session)
                beat_state = BeatState(timestamp, process, file, auditd)

                # # TODO: the current code is to add dict format data
                # self.events.append(beat_state)
                stashes.append(beat_state)
        return stashes


def parse():
    f = open('../../naive_test/auditbeat', 'r')
    for line in f.readlines():
        js_list.append(json.loads(line))


if __name__ == '__main__':
    parser = LogParser()
    parser.parse()
    import IPython
    IPython.embed()
