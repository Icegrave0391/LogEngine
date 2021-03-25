from logengine.factory import ISA, ArchInfo, syscall_analysis_table
from logengine.factory.block import Block
from logengine.pt import PTParser, InsnState, InsnManager
from logengine.audit import *
from logengine.audit import BeatState, ProvenanceManager
from capstone import CsInsn, CS_OP_IMM, CS_OP_REG, CS_OP_MEM
from typing import Optional, List, Union

import angr.project

from deprecated.sphinx import deprecated
import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)



class Project:
    """
    The main class of logengine
    # TODO(): Support multi-thread or process
    """
    def __init__(self, exec: str,
                 audit_parser: LogParser=None,
                 pt_parser: PTParser=None,
                 isa_util=None,
                 audit_log_file="./naive_test/auditbeat_toy",
                 pt_log_file="./naive_test/pt_toy_withoutxed_nofilter"
                 ):
        log.info(f"Creating analysis project for {exec}...")
        self.exec = exec
        self.audit_parser = audit_parser if audit_parser is not None else LogParser(lpath=audit_log_file)
        self.pt_parser = pt_parser if pt_parser is not None else PTParser(lpath=pt_log_file)
        self.isa_util = isa_util
        self.fpath_audit = audit_log_file
        self.fpath_pt = pt_log_file
        self._pt_stashes = None
        self._audit_stashes = None

        self._pt_manager = None
        self._audit_manger = None
        self.proc_pt_stashes = self._init_proc_ptstashes()
        self.proc_audit_stashes = self._init_proc_auditstashes()
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

    @property
    def audit_manager(self):
        if self._audit_manger is None:
            self._audit_manger = ProvenanceManager(self.audit_stashes)
        return self._audit_manger

    def _init_proc_ptstashes(self):
        """
        filter the original pt stashes retrieved from pt trace log file,
        :return: proc_ptstashes, which are the stashes from the process beginning
        """
        return self.pt_manager.proc_start_filter(self.exec)

    def _init_proc_auditstashes(self):
        """
        filter the original audit stashes retrieved from auditbeat log file,
        :return: proc_auditstashes, which are the stashed from the process beginning
        """

        def exec_filter(beat: BeatState):
            if beat.get_process_info(ProcessInfo.exec) == self.exec:
                return True
            return False

        return self.audit_manager.filter(filter=exec_filter, filter_syscall=True)

    def _init_controlflow_blocks(self):
        """
        Recover all the basic-blocks of the process, and the control flow between those blocks.
        """
        log.info(f"Start to generate the control flow and basic blocks...")
        # Make a shallow copy of the process's stashes
        shallow_copied = self.proc_pt_stashes.copy()

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

    def construct_provenence_graph(self,
                                   stashes: List[BeatState],
                                   save_name:str="example",
                                   save_visualized=True):
        if not isinstance(self.audit_manager, ProvenanceManager):
            log.error(f"Project {self}'s audit_manager {self.audit_manager} is not a type ProvenanceManager.")
            return

        graph =self.audit_manager.construct_pn_graph(stashes=stashes)
        if save_visualized:
            self.audit_manager.visualize(name=save_name)
        return graph


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
            sys_unit = SyscallUnit(self, i, sys_name)
            syscall_blocks.append(sys_unit)

        return syscall_blocks

    def create_angr_project(self, execution="/Users/chuqiz/2021/capstone/toy_pt/toy"):
        """
        Create a whole angr.project via the project's execution file, and rebase the base_addr
        according to the pt trace (due to PIE, the binary is not loaded at vmem 0x400000 in memory)
        """
        log.info(f"creating an angr.Project from binary {execution}")
        from cle import Loader

        """ 1. load by cle at default vmem base, to locate the entry offset """
        load = Loader(execution, auto_load_libs=False, use_system_libs=False)
        _start_offset = load.main_object.entry - load.main_object.mapped_base

        base_addr = self.proc_pt_stashes[0].ip - _start_offset
        log.info(f"The main binary has been loaded rebased at {hex(base_addr)} to align PT log.")
        """ 2. create project """
        load_options = {
            "main_opts": {"base_addr": base_addr},
            "auto_load_libs": False,
        }
        angr_proj = angr.Project(execution, load_options=load_options)
        return angr_proj


    @deprecated(version='1.0', reason='Should start a angr.project via the whole binary now')
    def create_angr_shellcode_project(self, rail_start=15264, rail_end=15997) -> angr.project.Project:
        """
        Create a angr.Project from a fragment of execution flow, to take analysis on that
        certain control flow (execution flow)
        :param rait_start: start location from the block_rail_set
        :param rail_end:   end location from the block_rail_set
        :return: angr.Project
        """
        # TODO(): how to deal with loop condition? maybe in register?
        # TODO(): I think maybe it's just make project from (sys_read callsite -> sys_write)

        uni_blocks = set()

        entry_block = self.blockrailset.get_block_from_rail_idx(rail_start)

        # 0.0 create a plt table map
        plt_map = {}

        # 1.0 list all the unique basic blocks for the project
        for i in range(rail_start, rail_end+1):
            blk = self.blockrailset.get_block_from_rail_idx(i)
            uni_blocks.add(blk)

            # 1.0.1 handle the plt table memory location (memory ptr type jmp)
            #       i.e.  jmp qword ptr [rip + 0x2015f2] -> fgets@plt+0x0
            #             could only handle %rip type memory base addr

            j_insn = blk.capstone.insns[-1].insn
            # memory-addressing type
            if len(j_insn.operands) and j_insn.operands[0].type == CS_OP_MEM:
                mem_operand = j_insn.operands[0].mem
                reg_base = mem_operand.base
                if j_insn.reg_name(reg_base) == 'rip':
                    # get the memory location
                    tar_memory = (j_insn.address + mem_operand.disp) * mem_operand.scale

                    # get the memory pointer content
                    tar_addr = self.blockrailset.get_block_from_rail_idx(i+1).addr

                    # update plt map
                    plt_map[tar_memory] = tar_addr


        # 1.1 generate Project from the entry_block's address
        log.info(f"Creating angr_project from load_address: {hex(entry_block.addr)}")
        angr_proj = angr.project.load_shellcode(entry_block.bytes,
                                                arch="amd64",
                                                start_offset=entry_block.addr,
                                                load_address=entry_block.addr)

        # 1.2 manually add other blocks to the angr_proj.loader.memory, for completing the
        #     project's memory space

        # 1.2.1 add basic block memorys
        for each_block in uni_blocks:
            if each_block.addr == entry_block.addr:
                continue

            log.debug(f"each block addr: {hex(each_block.addr)}")

            backers = angr_proj.loader.memory.backers(addr=each_block.addr)
            try:
                mem_addr, _ = next(backers)
                log.debug(f"backer addr: {hex(mem_addr)}")
                # backer behind block, so create a new backer
                if mem_addr > each_block.addr:
                    angr_proj.loader.memory.add_backer(start=each_block.addr,
                                                       data=each_block.bytes)
                else:
                    angr_proj.loader.memory.store(addr=each_block.addr,
                                                  data=each_block.bytes)
                # angr_proj.loader.memory.update_backer(start=each_block.addr,
                #                                       data=each_block.bytes)

            except StopIteration:
                """ not found backer """
                angr_proj.loader.memory.add_backer(start=each_block.addr,
                                                   data=each_block.bytes)

        # 1.2.2 add plt memorys
        for plt_addr, plt_tar in plt_map.items():
            bs = int.to_bytes(plt_tar, 8, byteorder="little")
            angr_proj.loader.memory.add_backer(start=plt_addr,
                                               data=bs)
        return angr_proj


class SyscallUnit:
    """
    A syscall unit related to the pt execution flow, which reveals syscall name, relevant block, process info
    and it's location at execution flow (blockrailset).
    Also, the syscall unit will show the map to its caller API info (libc API, i.e. sys_read <--caller-- fgets),
    including caller's location, relevant block, callername and processInfo
    """
    __slots__ = ["proj", "sys_rail_idx", "sys_name", "plt_rail_idx", "plt_func_name", "exec"]

    libc_caller_map = {
        "openat": ["open", "fopen"], "open": ["open", "fopen"],
        "read": ["read", "fgets"],
        "write": ["write", "fputs"],
        "close": ["close", "fclose"]
    }

    def __init__(self, proj: Project, sys_rail_idx: int, sys_name:str):
        self.proj = proj
        self.sys_rail_idx = sys_rail_idx  # location at project's blockrailset
        self.sys_name = sys_name
        self.plt_rail_idx, self.plt_func_name = self._resolve_plt(start=sys_rail_idx)
        self.exec = self.proj.exec

    def _resolve_plt(self, start):
        """
        resolve the syscall to its relevant up-layer libc caller function i.e. sys_read <--caller-- fgets
        The general call chain shouldbe :
            <user execfile> ---> 'call libc_func@plt'<user execfile> --> <libc execfile> --> syscall
        So the steps should be:

        1. take backward track from syscall site to the first place at <user execfile>, that should be plt instr
           if not, return None for the error case
        2. check the legitimacy of plt, for example, if read maps to fputs or fclose, that a wrong case
        3. when encountering an illegal match, it should skip that fragment of <user execfile> code, and take a
           new round of iteration, until finding the correct place
        """
        log.info(f"starting at:{start}, to resolve libc function at plt callsite for syscall {self.sys_name}\
         at {self.sys_rail_idx}")
        brset = self.proj.blockrailset

        def get_plt_idx(start):
            """
            get the expected 'call plt' instruction location at blockrailset
            """
            for i in range(start, -1, -1):
                block = brset.get_block_from_rail_idx(i)
                if block.exec != self.proj.exec:
                    continue
                return i, block
            return None, None

        def check_plt_legitimacy(plt_loc, block: Block):
            """
            check the legitiaecy of plt caller,
            as a observation before, there may be an unknown error : write syscall after fclose
            :param plt_loc:
            :param block:
            :return: (stop_flag: Bool, legitimacy_flag: Bool, func_name)
                    The func_name is useful only when legitimacy_flag = True
            """
            call_plt_insn = block.capstone.insns[-1].insn
            istate = self.proj.pt_manager.get_insn(call_plt_insn.address, self.proj.proc_pt_stashes)
            is_plt, func_name = istate.plt_info()
            if not is_plt:
                log.warning(
                    f"did not find relevant plt table function for syscall {self.sys_name} , at rail index {self.sys_rail_idx}")
                return True, None, func_name   # should stop immediately, error occurred

            if self.sys_name in SyscallUnit.libc_caller_map.keys():
                if not func_name in SyscallUnit.libc_caller_map[self.sys_name]:
                    log.debug(f"resolved illegal libc function {func_name}")
                    return False, False, func_name

            log.debug(f"resolved libc function {func_name} successfully")
            return False, True, func_name

        """1. take a backward iterate to get first plt location"""
        plt_loc, block = get_plt_idx(start=start)
        # error occurred, stop and return none result
        if not plt_loc:
            return None, None

        """2. check the legitimacy of the result"""
        should_stop, legitimacy, func_name = check_plt_legitimacy(plt_loc, block)
        # error occurred, stop and return none result
        if should_stop:
            return None, None
        # found a legitimate result, return the plt_loc at railset and its function name
        if legitimacy:
            return plt_loc, func_name

        """
        3. failed to map a legal libc function, should skip the code fragment at <user execfile>
           and take another backtrack
        """
        prev_libc = 0
        # skip the code fragment at <user execfile>
        for i in range(plt_loc, -1, -1):
            block = self.proj.blockrailset.get_block_from_rail_idx(i)
            # find previous libc procedure
            if block.exec == self.proj.exec:
                continue
            prev_libc = i
            break
        return self._resolve_plt(prev_libc)

    def __repr__(self):
        return f"SyscallUnit ({self.sys_name} at {self.sys_rail_idx}) -> ({self.plt_func_name} at {self.plt_rail_idx})"


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
        """
        get block from the block_address
        """

        for blk in self.blocks:
            if blk.addr == blk_addr:
                return blk

    def get_block_from_rail_idx(self, rail_idx):
        """
        get block from rail index
        """
        try:
            block_addr = self.rail[rail_idx]
        except IndexError:
            raise IndexError(f"{rail_idx} out of range {len(self.rail)}")

        return self.get_block(block_addr)

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
                ids.append(i)
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
        reversed_insns = loc_block.capstone.insns.copy() # make a shallow copy
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
