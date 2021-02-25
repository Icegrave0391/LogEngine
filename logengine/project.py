from logengine.factory import ISA, ArchInfo
from logengine.factory.block import Block
from logengine.pt import PTParser, InsnState, InsnManager
from logengine.audit import *
from logengine.audit import BeatState, ProvenanceManager

from typing import Optional, List, Union
import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class Project:
    """
    The main class of logengine
    # TODO(): Support multi-thread or process
    """
    def __init__(self, exec: str,
                 audit_parser: LogParser,
                 pt_parser: PTParser,
                 isa_util=None,
                 audit_log_file="./naive_test/auditbeat",
                 pt_log_file="./naive_test/pt_wget_withoutxed"
                 ):
        log.info(f"Creating analysis project for {exec}...")
        self.exec = exec
        self.audit_parser = audit_parser
        self.pt_parser = pt_parser
        self.isa_util = isa_util
        self.fpath_audit = audit_log_file
        self.fpath_pt = pt_log_file

        self._pt_stashes = None
        self._audit_stashes = None

        self._pt_manager = None
        self._proc_pt_stashes = self._init_proc_ptstashes()
        # block
        self.blockrailset = BlockRailSet()
        # construct control flow
        self._init_controlflow_blocks()

    @property
    def pt_stashes(self):
        if self._pt_stashes is None:
            self._pt_stashes = self.pt_parser.retrieve_raw()
        return self._pt_stashes

    @property
    def audit_stashes(self):
        if self._audit_stashes is None:
            self._audit_stashes = self.audit_parser.parse()
        return self._audit_stashes

    @property
    def pt_manager(self):
        if self._pt_manager is None:
            self._pt_manager = InsnManager(self.pt_stashes)
        return self._pt_manager

    def _init_proc_ptstashes(self):
        return self.pt_manager.proc_start_filter(self.exec)

    def _init_controlflow_blocks(self):
        """
        Recover all the basic-blocks of the process, and the control flow between those blocks.
        """
        log.info(f"Start to generate the control flow and basic blocks...")
        # Make a shallow copy of the process's stashes
        shallow_copied = self._proc_pt_stashes.copy()

        while len(shallow_copied):
            # basic block states
            bb_states = []
            # determine all instructions in a basic block
            for insn_state in shallow_copied:
                bb_states.append(insn_state)
                if insn_state.flag:  # A flag of insn_state means it could take a branch or jump
                    break

            # remove from the shallow copy
            for s in bb_states:
                shallow_copied.remove(s)

            # bytestring for basic block
            byte_string = self.pt_manager.generate_bytestring(bb_states)
            # construct the basic block
            bblock = Block(
                addr=bb_states[0].ip,
                byte_string=byte_string,
                project=self,
                isa_util=self.isa_util,
                size=None,
                exec=bb_states[0].exec
            )
            # update railtrack
            self.blockrailset.update_rail(block=bblock)

    # def syscall_chain(self):

class BlockRailSet:
    """
    A set of blocks generated during the process's life-cycle.
    And the execution of the process will be tracked in the rail.
    """

    def __init__(self, blocks:Optional[List[Block]]=None):
        self._blocks = blocks if blocks else set()
        self.rail = list()

    @property
    def blocks(self):
        return self._blocks

    def get_block(self, addr):
        for blk in self.blocks:
            if blk.addr == addr:
                return blk

    def update_rail(self, block):
        addr = block.addr
        self.rail.append(addr)
        self.blocks.add(block)

    def get_rail_idxs(self, block):
        addr = block.addr
        ids = []
        for i in range(len(self.rail)):
            r = self.rail[i]
            if r == addr:
                ids.append(r)
        return ids

    def describe(self, rail_idx):
        addr = self.rail[rail_idx]
        blk = self.get_block(addr)
        blk.pp
