import logging
from typing import List, Callable, ByteString

from .insn_state import InsnState
from logengine.factory import ISA, ArchInfo

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class InsnManager:
    """
    Base class of managers.
    """
    # TODO(): refine some comman design patterns to the basic class
    def __init__(self, stashes:List[InsnState]):
        self.pt_stashes = stashes

    def proc_start_filter(self, exec, filter_insn=True):
        log.info(f"Enabled process filter, to the start of process {exec}")
        sources = self.pt_stashes
        if filter_insn:
            sources = self.filter_insn()
        # locate to the start
        loc = 0
        for i in range(len(sources)):
            insn = sources[i]
            if exec == insn.exec:
               loc = i
               break

        if not loc:
            log.warning(f"Didn't find process start.")
            return None
        return sources[loc:]

    def filter_insn(self):
        stashes = []
        for insn in self.pt_stashes:
            if insn.insn_type:
                stashes.append(insn)
        return stashes

    def get_insn(self, addr, stashes: List[InsnState]):
        """
        Get insn from address
        """
        for istate in stashes:
            if istate.ip == addr:
                return istate
        log.warning(f"Did not find InsnState at address {hex(addr)}")
        return None

    def generate_bytestring(self, insns: List[InsnState]):
        """
        Generate code-bytestring from given textual assembly instructions
        """
        isa_util = ISA(ArchInfo())
        byte_string = b''
        for insn_state in insns:
            insn = insn_state.insn
            ip = insn_state.ip
            if not isinstance(insn, ByteString):
                bytes = isa_util.asm(insn, ip)
            else:
                bytes = insn
            byte_string += bytes
        return byte_string

