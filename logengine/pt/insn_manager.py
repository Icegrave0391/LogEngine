import logging
from typing import List, Callable, ByteString, Optional
import os
import logengine
import pickle
from deprecated.sphinx import deprecated

from .insn_state import InsnState
from logengine.factory import ISA, ArchInfo

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

base_root_dir = "LogEngine"

class InsnManager:
    """
    Base class of managers.
    """
    # TODO(): refine some comman design patterns to the basic class
    def __init__(self, stashes:List[InsnState], pickle_path=None,
                 root_dir="LogEngine", file_dir="database",
                 project=None):
        self.origin_pt_stashes = stashes
        self._root_dir = root_dir
        self._file_dir = file_dir
        self._pickle_path = pickle_path
        self.project = project

    @property
    def pickle_path(self):
        if self._pickle_path is None:
            exec_name = self.project.exec if self.project else "tmp"
            self.pickle_path = exec_name
        return self._pickle_path

    @pickle_path.setter
    def pickle_path(self, exec_name):
        abs_dir = os.path.abspath(os.path.dirname(__name__))
        abs_dir = abs_dir[: abs_dir.find(self._root_dir) + len(self._root_dir)]
        abs_dir = os.path.join(abs_dir, self._file_dir)
        if not os.path.exists(abs_dir):
            os.makedirs(abs_dir)

        idx = exec_name.find(".")
        if idx < 0:
            idx = None

        self._pickle_path = os.path.join(
            abs_dir, exec_name[:idx] + ".pk"
        )

    def filter_insn(self, stashes: Optional[List[InsnState]]=None):
        s = []
        origin_stashes = stashes if stashes is not None else self.origin_pt_stashes
        for insn in origin_stashes:
            if insn.insn_type:
                s.append(insn)
        return s

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

    def save_data(self, stashes: List[InsnState], name=None):
        if name is not None:
            self.pickle_path = name
        with open(self.pickle_path, "w") as f:
            pickle.dump(stashes, f)

    @deprecated(version="1.0", reason="filter exec from the raw_parser to save space.")
    def proc_start_filter(self, exec, filter_insn=True, source=None):
        log.info(f"Enabled process filter, to the start of process {exec}")
        sources = self.origin_pt_stashes if not source else source
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
