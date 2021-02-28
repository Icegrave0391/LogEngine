from logengine.factory import ISA, ArchInfo, syscall_analysis_table
from logengine.factory.block import Block
from logengine.pt import PTParser, InsnState, InsnManager
from logengine.audit import *
from logengine.audit import BeatState, ProvenanceManager
from capstone import CsInsn, CS_OP_IMM, CS_OP_REG
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
        # syscall chain
        self.syscall_chain = self.construct_syscall_chain(self.blockrailset)

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

    def construct_syscall_chain(self, blockrailset):
        """
        Construct a syscall chain from the control flow.
        Find all syscall blocks in the control flow.

        :param blockrailset:
        :return: syscall blocks, a list of [tuple(rail_index, block, syscall_name)]
        """
        log.info(f"Constructing syscall analysis chain for project.")
        syscall_blocks = []

        for i in range(len(blockrailset.rail)):
            addr = blockrailset.rail[i]
        # for addr in blockrailset.rail:
            block = blockrailset.get_block(addr)

            if not block.is_syscall:
                continue

            # get instruction 'mov eax, 0x..(syscall number)'
            # Here I use the regular format of sysc
            rax_write_insn: CsInsn = block.capstone.insns[-2]
            _, reg_write = rax_write_insn.regs_access()

            if (not len(reg_write)
                or (not rax_write_insn.reg_name(reg_write[0]) == "eax"
                    and not rax_write_insn.reg_name(reg_write[0]) == "rax"
                )
                or not rax_write_insn.operands[1].type == CS_OP_IMM
            ):
                # try to resolve via block's def use chain
                syscall_value = self.blockrailset.resolve_register("eax", i, cross_block=True)
                if syscall_value is None:
                    log.warning(f"{hex(rax_write_insn.address)}: {rax_write_insn.mnemonic} {rax_write_insn.op_str} resolved failed.")
                    continue
            else:
                # resolve syscall value directly
                syscall_value = rax_write_insn.operands[1].imm

            if not syscall_value in syscall_analysis_table.keys():
                continue

            sys_name = syscall_analysis_table[syscall_value]
            syscall_blocks.append((i, block, sys_name))

        return syscall_blocks




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

    def get_block(self, blk_addr):
        for blk in self.blocks:
            if blk.addr == blk_addr:
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
        blk.capstone.pp()

    def resolve_register(self, reg_name: str, rail_idx: int, cross_block=False):
        """
        resolve register value of the block
        # TODO(): Just a prototype for resolve eax/rax now

        # TODO(): the resolver could only resolve behaviors like:
        # TODO():   mov eax, 0x10;  xor eax, eax;

        :param reg_name: register name to be resolved
        :param rail_idx: from the index in the rail (control flow)
        :param cross_block: should make analysis between blocks
        :return: the resolved value
        """

        # find the locate where register has been written

        def dfs_find_written_insn(reg_name, rail_idx, block_rail_set, cross_block):
            """
            Take dfs to locate the instruction where the register 'reg_name' has been written
            """
            block = block_rail_set.get_block(block_rail_set.rail[rail_idx])
            du_chain = block.block_def_use()

            for item in du_chain:
                insn_addr, definings, rws = item
                if reg_name in rws: # search out the instruction
                    return (item, rail_idx)

            if cross_block:
                if rail_idx  == 0:
                    return (None, None)
                return dfs_find_written_insn(reg_name=reg_name,
                                             rail_idx=rail_idx-1,
                                             block_rail_set=block_rail_set,
                                             cross_block=cross_block)
        # get the instruction in the block and the relevant rail index of the block
        item, idx = dfs_find_written_insn(reg_name, rail_idx, self, cross_block)
        if not item:
            log.warning(f"Resolve register {reg_name} from rail index {rail_idx} failed.")
            return None

        rw_insn_addr = item[0]
        loc_block: Block = self.get_block(self.rail[idx])

        # take a reverse of the instructions in that block, since we should do backward traverse
        reversed_insns = loc_block.capstone.insns # make a shallow copy
        reversed_insns.reverse()

        idx, rw_insn = loc_block.capstone.get_insn(rw_insn_addr, reversed_insns)

        # retrieve the value of register
        if rw_insn.mnemonic == "mov":
            if rw_insn.operands[1].type == CS_OP_IMM:
                return rw_insn.operands[1].imm

        elif rw_insn.mnemonic == "xor":
            if rw_insn.operands[1].type == CS_OP_REG:
                if rw_insn.operands[0].reg == rw_insn.operands[1].reg: # xor reg, reg (reg <- 0)
                    return 0

        log.warning(f"Resolve register {reg_name} from rail index {rail_idx} failed.")
        return None
