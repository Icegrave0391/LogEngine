import json
import sys
from typing import List, Optional, Dict
from .retrievers import compiled_patterns, raw_retreiver
from .insn_state import InsnState
import re

import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

pt_test_file = 'naive_test/pt_wget_withoutxed'


class PTParser(object):
    def __init__(self,
                 lpath: str = pt_test_file,
                 outpath: Optional[str] = './log_output/pt_res'
                 ):
        self.type = type
        self.path_pttrace = lpath
        self.path_out = outpath
        self.events = list()
        log.info(f'Initialized a intel_pt log parser.')

    def retrieve_raw(self, filter_mode=True, custom_filters: Optional[List[re.Pattern]]=None, already_xed_decode=False) -> List[InsnState]:
        """
        pre-process the raw perf script outpout file
        """
        log.info(f'Starting to retrieve the raw intel_pt output file {self.path_pttrace}...')
        stashes = list()
        with open(self.path_pttrace, 'r') as f:
            for line in f.readlines():
                if filter_mode and self._raw_linefilter(line, custom_filters) is True:
                    continue
                if already_xed_decode:
                    insn_trace = line.strip().split('\t')
                else:
                    insn_trace = line.strip().split("insn:")
                insn_trace = list(filter(None, insn_trace))

                if len(insn_trace) > 2 or len(insn_trace) < 1:
                    raise ValueError(f'Invalid trace line: {line}')
                if len(insn_trace) == 1:
                    comm_infoset, insn = insn_trace[0], None
                else:
                    comm_infoset, insn = insn_trace
                    if not already_xed_decode: # convert string format code to bytecode
                        insn = self.retrieve_insn_bytecode(insn)

                # extract flag field first
                flag = re.findall(r'u:([a-zA-Z ]+)', comm_infoset)[0]
                if flag:
                    flag = re.sub(r' [a-fA-F0-9]+]', '', flag).strip()
                    comm_infoset = comm_infoset.replace(flag, '')

                comm_infoset = comm_infoset.strip().split()
                if not len(comm_infoset) == raw_retreiver['fields_noflag_len']:
                    raise ValueError(f'failed to parse set: {comm_infoset}')

                comm, r_tpid, cpuinfo, r_timestamp, _, r_insn_type, ip, symwoff, exec = comm_infoset

                tid, pid = raw_retreiver['t&pid'](r_tpid)
                timestamp = r_timestamp.replace(':', '')
                insn_type = 1 if r_insn_type.find('instruction') >= 0 else 0
                ip = int(ip, 16)
                sym, offset = raw_retreiver['symwoff'](symwoff)
                execf = raw_retreiver['exec'](exec)

                state = InsnState(comm, tid, pid, cpuinfo, timestamp, insn_type, flag, ip, sym, offset, execf, insn)
                stashes.append(state)
        return stashes

    def _raw_linefilter(self, line: str, custom_filters: Optional[List[re.Pattern]] = None) -> bool :
        """
        Determine if the line should be filtered
        """
        # Default filters
        for p in compiled_patterns:
            if p.search(line) is not None:
                # log.info(f'filtered line: {line}')
                return True
        # Custom filters
        if custom_filters is not None:
            for cp in custom_filters:
                if cp.search(line) is not None:
                    return True
        return False

    def retrieve_insn_bytecode(self, insn:str):
        """
        Convert the string type byte code (like: '48 3d 00 f0 ff ff') to bytecode
        """
        def to_hex(s):
            return int(s, 16)
        str_list = insn.strip().split()

        hex_list = list(map(to_hex, str_list))
        return bytes(hex_list)
