from typing import List, Set, Optional, TYPE_CHECKING, Union, Iterable, Dict, Tuple
import logging
from visualize import magic_graph_print as mgp
log = logging.getLogger(__name__)

from ..execution_flow import ExecutionFlow

import angr

from angr.calling_conventions import SimCC
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.heap_allocator import HeapAllocator
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.unknown_size import UnknownSize, UNKNOWN_SIZE
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag, ParameterTag, ReturnValueTag, Tag
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Parameter, Tmp
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.dataset import DataSet
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.undefined import Undefined, UNDEFINED
from angr.engines.light import RegisterOffset, SpOffset
from angr.knowledge_plugins.key_definitions import LiveDefinitions
if TYPE_CHECKING:
    from angr.code_location import CodeLocation
    from angr.analyses.reaching_definitions.dep_graph import DepGraph
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
    from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Parameter


class DefinitionUtil:

    def __init__(self, project: angr.Project):
        self.project = project
        self._heap_allocator = None

    @property
    def heap_allocator(self):
        if self._heap_allocator is None:
            self._heap_allocator = HeapAllocator(canonical_size=4)
        return self._heap_allocator

    def definition_data_represent_address(self, mem_addr):
        """
        determine whether a definition data could represent mem_addr
        """
        return (
            isinstance(mem_addr, int) or
            (isinstance(mem_addr, SpOffset) and isinstance(mem_addr.offset, int)) or
            (isinstance(mem_addr, HeapAddress) and isinstance(mem_addr.value, int))
        )

    def create_arg_atoms(self, cc: SimCC) -> List[Register]:
        """
        create all the atoms represent the function's arguments, conducted by function's cc
        """
        # SimRegArg(SimFunctionArgument)
        # args = cc.args
        args = cc.arg_locs()
        # RegisterAtom
        arg_atoms: List[Register] = []
        for arg in args:
            arg_atoms.append(Atom.from_argument(arg, self.project.arch.registers))

        return arg_atoms

    def get_defs_by_register_atom(self, atoms: List[Register], index, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        Get a certain register atom's all definitions with all of the data, constrained by state and codeloc
        :param atoms:  A list of register atoms
        :param index:  The index to locate the certain register atom
        :param state:  ReachingDefinitionState
        :param codeloc:
        :return:       (atom, definition.data: Set, Set[Definition])
        """
        atom, data = atoms[index], set()
        current_defs: Iterable[Definition] = state.register_definitions.get_objects_by_offset(atom.reg_offset)
        for defi in current_defs:
            data.update(defi.data)
        if len(data) == 0:
            data.add(UNDEFINED)
            dataset = DataSet(data, atom.bits)
            state.kill_and_add_definition(atom, codeloc, dataset)
        return atom, data, current_defs

    def kill_memory_definitions(self, mem_addr_data: Set,
                                  state: 'ReachingDefinitionsState',
                                  codeloc: 'CodeLocation',
                                  function: Optional[Function]=None):
        """
        Kill some memory_definitions for a rd_state.
        :param mem_addr_data: data represents the memory address
        """
        if all(not self.definition_data_represent_address(mem_addr) for mem_addr in mem_addr_data):
            log.info(f"Memory address all undefined, function: {function.name}, codeloc: {codeloc}")
            return

        for mem_addr in mem_addr_data:

                if not self.definition_data_represent_address(mem_addr):
                    log.info(f"Has undefined memory address, function: {function.name}, codeloc: {codeloc}")
                    continue

                if isinstance(mem_addr, int): # memory location
                    exist_memdefs: Set[Definition] = state.memory_definitions.get_objects_by_offset(mem_addr)
                elif isinstance(mem_addr, SpOffset): # stack
                    exist_memdefs: Set[Definition] = state.stack_definitions.get_objects_by_offset(mem_addr.offset)
                else: # heap
                    exist_memdefs: Set[Definition] = state.heap_definitions.get_objects_by_offset(mem_addr.value)

                for memdef in exist_memdefs:
                    state.kill_definitions(memdef.atom, memdef.codeloc)

    def create_memory_dependency(self, mem_addr_data: Set,
                                 state: 'ReachingDefinitionsState',
                                 codeloc: 'CodeLocation',
                                 function: Optional[Function]=None,
                                 default_content: Optional[Union[Undefined, Set]]=UNDEFINED):
        """
        add the memory dependency(use) for a reaching_definition state.
        :param mem_addr_data: a set of data which could potentially represent the memory location address
        :param default_content: when there is no such memory_definitions represented by mem_addr,
                                create that definition using that default_content in memory(UNDEFINED)
        """
        if all(not self.definition_data_represent_address(mem_addr) for mem_addr in mem_addr_data):
            log.info(f"[create_memory_dependency] Memory address all undefined, function: {function.name}, codeloc: {codeloc}")
            return



        for mem_addr in mem_addr_data:
            if not self.definition_data_represent_address(mem_addr):
                log.info(f"[create_memory_dependency] Has undefined memory address, function: {function.name}, codeloc: {codeloc}")
                continue

            memdefs = self._get_mem_def(state, mem_addr)

            # not in mem_def: create memdef
            if len(memdefs) == 0:
                self.create_memory_definition({mem_addr}, None, state, codeloc, function, default_content)
                # re-get the memory definitions
                memdefs = self._get_mem_def(state, mem_addr)

            for memdef in memdefs:
                state.add_use_by_def(memdef, codeloc)

    def create_memory_definition(self, mem_addr_data: Iterable,
                                 mem_sz_data: Optional[Iterable],
                                 state: 'ReachingDefinitionsState',
                                 codeloc: 'CodeLocation',
                                 function: Optional[Function]=None,
                                 content_data: Optional[Union[Undefined, Set]]=UNDEFINED
                                 ):
        """
        Create a memory_location definition, by a set of data to determine the memory_address, and a set of
        optional data to determine the size.
        Here we'd like to create the memory_location for thr maximum size determined by mem_sz_data, if the data
        is provided, else size 1 (Whatever, the size is unimportant).
        :param mem_addr_data: a set of data in a definition's dataset which represents the memory address
        :param mem_sz_data:   a set of data in a definition's dataset which represents the memory size
        :param state:         the ReachingDefinitionState
        :param codeloc:
        :param function:      the certain external function (like fgets, )
        :return:
        """
        if all(not self.definition_data_represent_address(mem_addr) for mem_addr in mem_addr_data):
            log.info(f"[create_memory_definition] Memory address all undefined, function: {function.name if function else '?'}, codeloc: {codeloc}")
            log.info(f"[create_memory_definition] Created failed.")
            return
        # get the maximum size
        max_sz = 1
        if mem_sz_data is not None:
            max_in_data = max(list(filter(lambda x: isinstance(x, int), mem_sz_data)))
            max_sz = 1 if max_in_data < 1 else max_in_data

        for mem_addr in mem_addr_data:
            if type(mem_addr) is Undefined or not self.definition_data_represent_address(mem_addr):
                log.info('Memory address undefined, ins_addr = %#x.', codeloc.ins_addr)
                log.info(f"[create_memory_definition] Has undefined memory address, function: {function.name if function else '?'}, codeloc: {codeloc}")
                continue
            # handle a resolvable address
            if function:
                tags = {ParameterTag(function=function.addr, metadata={'tagged_by': function.name,
                                                                    'mem_addr': mem_addr,
                                                                    'mem_sz': max_sz
                                                                    })}
            else:
                tags = None
            memloc = MemoryLocation(mem_addr, max_sz)
            # add definitions
            dataset = DataSet(content_data, max_sz * 8)
            state.kill_and_add_definition(memloc, codeloc, dataset, tags=tags)

    def create_ret_atom(self, cc: SimCC) -> Register:
        """
        Create a return register atom, conducted by the function's cc
        """
        ret_reg = cc.return_val
        return Atom.from_argument(ret_reg, self.project.arch.registers)

    def create_ret_val_definition(self, function: Function, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation', data=UNDEFINED):
        ret_reg = self.create_ret_atom(function.calling_convention)
        tags = {ReturnValueTag(function.addr, metadata={"tagged_by": function.name})}
        dataset = DataSet(data, ret_reg.size * 8)
        state.kill_and_add_definition(ret_reg, codeloc, dataset, tags=tags)

    def allocate(self, state: 'ReachingDefinitionsState',
                 codeloc: 'CodeLocation',
                 size_data:Optional[Set]=None,
                 item_num_data: Optional[Set]=None,
                 function: Optional[Function]=None) -> Tuple[HeapAddress, Union[int, UnknownSize]]:
        """
        Allocate a heap memory location
        :param size_data: A set of data indicate the size of item, just consider the largest one
        :param item_num_data: A set of data indicate the number of items, just consider the largest one
        :return: HeapAddress, total_size
        """
        size, num = UNKNOWN_SIZE, UNKNOWN_SIZE
        if item_num_data is not None:
            int_data = list(filter(lambda x: isinstance(x, int), item_num_data))
            try:
                num = max(int_data)
            except ValueError:
                num = UNKNOWN_SIZE
        if size_data is not None:
            size_data = list(filter(lambda x: isinstance(x, int), size_data))
            try:
                size = max(size_data)
            except ValueError:
                size = UNKNOWN_SIZE
        if isinstance(size, int) and isinstance(num, int):
            size = size * num
        # allocate heap memory
        heap_addr: HeapAddress = self.heap_allocator.allocate(size)
        # create heap memory definition
        memloc = MemoryLocation(heap_addr, size if isinstance(size, int) else self.heap_allocator._canonical_size)
        if function:
            tags = {ParameterTag(function=function.addr, metadata={'tagged_by': function.name,
                                                                   'heap_addr': heap_addr,
                                                                   'heap_sz': size
                                                                   })}
        else:
            tags = None
        state.kill_and_add_definition(memloc, codeloc, data=DataSet(UNDEFINED, memloc.size * 8), tags=tags)
        return heap_addr, size

    def _get_mem_def(self, state: 'ReachingDefinitionsState', mem_addr) -> Set[Definition]:
        """
        Get all of the memory definitions (mem_definitions, stack_defs or heap_defs) by the mem_addr,
        ***based on the sumption*** that the mem_addr could represent a memory_location.
        :param mem_addr: a data which represents the mem_addr (type int: mem; SpOffset: stack; HeapAddress: heap)
        """
        if isinstance(mem_addr, int):  # memory location
            memdefs: Set[Definition] = state.memory_definitions.get_objects_by_offset(mem_addr)
        elif isinstance(mem_addr, SpOffset):  # stack
            memdefs: Set[Definition] = state.stack_definitions.get_objects_by_offset(mem_addr.offset)
        else:  # heap
            memdefs: Set[Definition] = state.heap_definitions.get_objects_by_offset(mem_addr.value)
        return memdefs


class WgetHandler(FunctionHandler):
    """
    My naive function handler to handle(hook for reaching-definitions) all of the external functions and
    create relevant def-use chain, for the first approach of static data-flow analysis.

    All of the handlers should follow the prototype of handle_fputs and handle_fgets, which have been tested
    for my own logic.
    """
    # g_local_live_definitions: Dict[int, LiveDefinitions] = {}

    def __init__(self, ef: Optional[ExecutionFlow]=None):
        self._analyses = None
        # self._local_func_stack = []
        self.project: 'angr.Project' = None
        self.util: 'DefinitionUtil' = None
        self._handle_plt = False
        self._plt_addr = None
        self._ef = None
        if ef is not None:
            self._ef = ef


    @property
    def handle_plt(self):
        return self._handle_plt

    @property
    def plt_addr(self):
        return self._plt_addr

    @property
    def heap_allocator(self):
        return self.util.heap_allocator

    @handle_plt.setter
    def handle_plt(self, v):
        self._handle_plt = v[0]
        self._plt_addr = v[1]

    def update_plt_observe(self, child_rda: ReachingDefinitionsAnalysis, live_definitions: LiveDefinitions):
        if not self.handle_plt:
            return

        ob_res: LiveDefinitions = child_rda.observed_results[("insn", self.plt_addr, OP_AFTER)]
        child_rda.observed_results[("insn", self.plt_addr, OP_AFTER)] = ob_res.merge(live_definitions)

    def hook(self, analysis):
        """
        Hook is just to pass the parent's RDA
        :param analysis:
        :return:
        """
        self._analyses = analysis      # parent rda
        self.project = analysis.project
        self.util = DefinitionUtil(self.project)
        return self

    def handle___errno_location(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int * __errno_location (void){ return &errno; }
        """
        __errno_location = self.project.kb.functions.function(name="__errno_location")
        """1. add return"""
        self.util.create_ret_val_definition(__errno_location, state, codeloc)
        return True, state

    def handle___ctype_get_mb_cur_max(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        size_t __ctype_get_mb_cur_max(void);
        """
        __ctype_get_mb_cur_max = self.project.kb.functions.function(name="__ctype_get_mb_cur_max")
        """1. add return"""
        self.util.create_ret_val_definition(__ctype_get_mb_cur_max, state, codeloc)
        return True, state

    # def handle_nl_langinfo(self):

    def handle_getpgrp(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        pid_t getpgrp(void);
        """
        getpgrp = self.project.kb.functions.function(name="getpgrp")
        self.util.create_ret_val_definition(getpgrp, state, codeloc)
        return True, state

    def handle_tcgetpgrp(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        pid_t tcgetpgrp(int fildes);
        """
        tcgetpgrp = self.project.kb.functions.function(name="tcgetpgrp")
        cc = tcgetpgrp.calling_convention

        arg_atoms = self.util.create_arg_atoms(cc)
        """1. add use"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. return val"""
        self.util.create_ret_val_definition(tcgetpgrp, state, codeloc)
        return True, state

    def handle_dcgettext(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        char * dcgettext (const char * domainname, const char * msgid, int category);
        """
        dcgettext = self.project.kb.functions.function(name="dcgettext")
        cc = dcgettext.calling_convention

        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)
        """1. add use for arguments"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        """2. add definition of ret"""
        self.util.create_ret_val_definition(dcgettext, state, codeloc)
        return True, state

    def handle___fdelt_chk(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        long int __fdelt_chk (long int d);
        """
        __fdelt_chk = self.project.kb.functions.function(name="__fdelt_chk")
        arg_atoms = self.util.create_arg_atoms(__fdelt_chk.calling_convention)

        # no prototype in calling convention?
        return True, state

    def handle__xstat64(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int ___xstat64 (int vers, const char *name, struct stat64 *buf);
        no prototype for function
        """
        __xstat64 = self.project.kb.functions.function(name="__xstat64")
        self.util.create_ret_val_definition(__xstat64, state, codeloc)
        return True, state

    def handle___freading(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int __freading(FILE *stream);
        """
        __freading = self.project.kb.functions.function(name="__freading")
        cc = __freading.calling_convention

        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)

        """1. add use for ther parameters"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. create return """
        self.util.create_ret_val_definition(__freading, state, codeloc)
        return True, state

    def handle_fflush(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int fflush(FILE *stream);
        """
        fflush = self.project.kb.functions.function(name="fflush")
        cc = fflush.calling_convention

        arg_atoms = self.util.create_arg_atoms(cc)
        """1. add use for args"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. create return"""
        self.util.create_ret_val_definition(fflush, state, codeloc)
        return True, state

    def handle_strchr(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        char *strchr(const char *s, int c);
        """
        strchr = self.project.kb.functions.function(name="strchr")
        cc = strchr.calling_convention

        arg_atoms = self.util.create_arg_atoms(cc)
        """1. add use"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. ret"""
        self.util.create_ret_val_definition(strchr, state, codeloc)
        return True, state

    def handle_clock_gettime(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int clock_gettime(clockid_t clock_id, struct timespec *tp);
        """
        clock_gettime = self.project.kb.functions.function(name="clock_gettime")

        arg_atoms = self.util.create_arg_atoms(clock_gettime.calling_convention)
        """1. add use for args"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. add return value"""
        self.util.create_ret_val_definition(clock_gettime, state, codeloc)
        return True, state

    def handle_wcwidth(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int wcwidth(wchar_t wc);
        """
        wcwidth = self.project.kb.functions.function(name="wcwidth")
        # no function prototype?
        self.util.create_ret_val_definition(wcwidth, state, codeloc)
        return True, state

    def handle_strlen(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        size_t strlen(const char *s);
        #TODO(): calc strlen from strings
        """

        strlen = self.project.kb.functions.function(name="strlen")
        cc = strlen.calling_convention

        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)
        """1. add use for the parameters"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        # get data
        rdi_atom, rdi_data, rdi_defs = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        """2. add dependecy for memory definition"""
        for mem_addr in rdi_data:
            if self.definition_data_represent_address(mem_addr):
                memdefs: Iterable[Definition] = state.memory_definitions.get_objects_by_offset(mem_addr)
                for memdef in memdefs:
                    state.add_use_by_def(memdef, codeloc)

        """3. create return value definition"""
        self.util.create_ret_val_definition(strlen, state, codeloc)
        return True, state

    def handle_strtol(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        long strtol(const char *restrict str, char **restrict endptr, int base);
        """
        strtol = self.project.kb.functions.function(name="strtol")
        arg_atoms = self.util.create_arg_atoms(strtol.calling_convention)

        rdi_atom, rdi_data, rdi_defs = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        rsi_atom, rsi_data, rsi_defs = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc)

        """1. kill origin definition """
        self.util.kill_memory_definitions(rsi_data, state, codeloc, strtol)
        """2. add use of args"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """3. add memory dependency"""
        self.util.create_memory_dependency(rdi_data, state, codeloc, strtol)
        """4. create memory def"""
        self.util.create_memory_definition(rsi_data, None, state, codeloc, strtol)
        """5. add return"""
        self.util.create_ret_val_definition(strtol, state, codeloc)
        return True, state


    def handle_inet_ntop(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        const char * inet_ntop(int af, const void * restrict src, char * restrict dst, socklen_t size);
        """
        inet_ntop = self.project.kb.functions.function(name="inet_ntop")
        arg_atoms = self.util.create_arg_atoms(inet_ntop.calling_convention)

        rsi_atom, rsi_data, _ = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc) # src
        rdx_atom, rdx_data, _ = self.util.get_defs_by_register_atom(arg_atoms, 2, state, codeloc) # dst
        rcx_atom, rcx_data, _ = self.util.get_defs_by_register_atom(arg_atoms, 3, state, codeloc) # size
        """1. kill dst memory region definitions"""
        self.util.kill_memory_definitions(rdx_data, state, codeloc, inet_ntop)
        """2. add use of args"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """3. add dependency for src memory"""
        self.util.create_memory_dependency(rsi_data, state, codeloc, inet_ntop)
        """4. create definition for dst memory"""
        self.util.create_memory_definition(rdx_data, rcx_data, state, codeloc, inet_ntop)
        """5. ret value for dst pointer"""
        self.util.create_ret_val_definition(inet_ntop, state, codeloc, rdx_data)
        return True, state

    def handle_fileno(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int fileno(FILE *stream);
        """
        fileno = self.project.kb.functions.function(name="fileno")
        arg_atoms = self.util.create_arg_atoms(fileno.calling_convention)
        """1. add use of args"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. add return value"""
        self.util.create_ret_val_definition(fileno, state, codeloc)
        return True, state

    def handle_fopen(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        # just pass that, don't change state for right now
        print(f"[handle fopen] codeloc: {codeloc}")
        return True, state

    def handle_fclose(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        print(f"[handle fclose] codeloc: {codeloc}")
        return True, state

    def handle_printf(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        print(f"[handle printf] codeloc: {codeloc}")
        return True, state

    def handle_puts(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        print(f"[handle puts] codeloc: {codeloc}")
        return True, state

    def handle_memset(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        void * memset(void *b, int c, size_t len);
        """
        memset = self.project.kb.functions.function(name="memset")
        arg_atoms = self.util.create_arg_atoms(memset.calling_convention)

        rdi_atom, rdi_data, rdi_defs = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        rsi_atom, rsi_data, rsi_defs = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc)
        rdx_atom, rdx_data, rdx_defs = self.util.get_defs_by_register_atom(arg_atoms, 2, state, codeloc)
        """1. kill origin defs for memloc"""
        self.util.kill_memory_definitions(rdi_data, state, codeloc, memset)
        """2. add use of args"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """3. create memory dependency"""
        self.util.create_memory_definition(rdi_data, rdx_data, state, codeloc, memset, rsi_data)
        """4. return"""
        self.util.create_ret_val_definition(memset, state, codeloc, rdi_data)
        return True, state

    def handle_memcpy(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        void * memcpy(void *restrict dst, const void *restrict src, size_t n);
        for simplify, just ignore size (parameter in %rdx) here.
        """
        memcpy = self.project.kb.functions.function(name="memcpy")
        cc = memcpy.calling_convention

        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)
        rdi_atom, rdi_data, rdi_defs = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        rsi_atom, rsi_data, rsi_defs = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc)
        rdx_atom, rdx_data, rdx_defs = self.util.get_defs_by_register_atom(arg_atoms, 2, state, codeloc)
        """1. add use for args"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. add dependency for memdefs (rsi)"""
        self.util.create_memory_dependency(rsi_data, state, codeloc, memcpy)
        """3. create memdefs (rdi)"""
        self.util.create_memory_definition(rdi_data, rdx_data, state, codeloc, memcpy)
        """4. return value """
        self.util.create_ret_val_definition(memcpy, state, codeloc, data=rdi_data)
        return True, state

    def handle_memcmp(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int memcmp(const void *s1, const void *s2, size_t n);
        #TODO(): memory copy
        """
        memcmp = self.project.kb.functions.function(name="memcmp")
        arg_atoms = self.util.create_arg_atoms(memcmp.calling_convention)
        rdi_atom, rdi_data, _ = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        rsi_atom, rsi_data, _ = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc)
        rdx_atom, rdx_data, _ = self.util.get_defs_by_register_atom(arg_atoms, 2, state, codeloc)
        """1. add use"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. create mem dependency(use)"""
        self.util.create_memory_dependency(rdi_data, state, codeloc, memcmp)
        self.util.create_memory_dependency(rsi_data, state, codeloc, memcmp)
        """3. return"""
        self.util.create_ret_val_definition(memcmp, state, codeloc)
        return True, state

    def handle_fgets(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        char * fgets(char * buffer, int size, FILE * stream) // rdi, rsi, rdx
        """
        fgets = self.project.kb.functions.function(name='fgets')
        cc = fgets.calling_convention

        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)

        """prototype - preparation"""
        # get all the current live_definitions relative to rdi
        rdi_atom, rdi_data, rdi_current_defs = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        rsi_atom, rsi_data, rdi_current_defs = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc)

        """0. delete already exist memdefs of rdi represented, it must be done here, because delete_definition will also
              clear relevant state.codeloc_use.
              thus it's necessary to delete exist definitions before adding those registers uses.
        """
        for mem_addr in rdi_data:
            if self.definition_data_represent_address(mem_addr):
                exist_memdefs: Iterable[Definition] = state.memory_definitions.get_objects_by_offset(mem_addr)
                for memdef in exist_memdefs:
                    state.kill_definitions(memdef.atom, memdef.codeloc)

        """1. add use for current definitions, indicating that the parameters have passed on"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        """2. determine the definition value, to create relevant memorylocation, and do:
              * delete already-exsited that certain memory-location defs (no)// updated: not do here
              * add new memory-location definition (yes)
        """
        # create all the certain memory locs
        self.util.create_memory_definition(rdi_data, rsi_data, state, codeloc, fgets)
        return True, state

    def handle_read(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        ssize_t read(int fd, void *buf, size_t count);
        """
        read = self.project.kb.functions.function(name="read")
        cc = read.calling_convention

        arg_atoms = self.util.create_arg_atoms(cc)
        rdi_atom, rdi_data, rdi_current_defs = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        rsi_atom, rsi_data, rsi_current_defs = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc)

        # 0. delete exist memory definitions
        for mem_addr in rdi_data:
            if self.util.definition_data_represent_address(mem_addr):
                exist_memdefs = state.memory_definitions.get_objects_by_offset(mem_addr)
                for memdef in exist_memdefs:
                    state.kill_definitions(memdef.atom, memdef.codeloc)

        # 1. add use for the parameter registers
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        # 2. create memory definitions
        self.util.create_memory_definition(rdi_data, rsi_data, state, codeloc, read)

    def handle_fputs(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        fputs(char * buffer, FILE * stream) // rdi, rsi
        """
        fputs = self.project.kb.functions.function(name='fputs')
        cc = fputs.calling_convention

        # SimRegArg(SimFunctionArgument)
        args = cc.args
        # RegisterAtom
        arg_atoms = self.util.create_arg_atoms(cc)
        """1. add use for current definitions, indicating that the parameters have passed on"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        """2. determine the use-value, to add dependency
        """
        # 2.1 first get all the current live_definitions relative to rdi
        rdi_atom, rdi_data, rdi_current_defs = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)

        # 2.2 add dependency
        for mem_addr in rdi_data:
            if self.definition_data_represent_address(mem_addr):
                memdefs: Iterable[Definition] = state.memory_definitions.get_objects_by_offset(mem_addr)
                for memdef in memdefs:
                    state.add_use_by_def(memdef, codeloc)

        import ipdb;ipdb.set_trace()
        return True, state

    def handle_write(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        ssize_t write(int fd, const void *buf, size_t count);   // rdi, rsi, rdx
        """
        write = self.project.kb.functions.function(name="write")
        cc = write.calling_convention
        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)

        """1. add use for current definitions, indicating that the parameters have passed on"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        """2. determine the use-value, to add dependency"""
        rsi_atom, rsi_data, rsi_current_defs = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc)

        # add dependency
        for mem_addr in rsi_data:
            if self.definition_data_represent_address(mem_addr):
                memdefs: Iterable[Definition] = state.memory_definitions.get_objects_by_offset(mem_addr)
                for memdef in memdefs:
                    state.add_use_by_def(memdef, codeloc)

        """ add return value """
        self.util.create_ret_val_definition(write, state, codeloc)
        return True, state

    def handle_socket(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        socket(int domain, int type, int protocal);
        :return: rax sockfd
        """
        socket = self.project.kb.functions.function(name="socket")
        cc = socket.calling_convention
        arg_atoms = self.util.create_arg_atoms(cc)

        """1. add use of current argument definitions"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        """2. create definition of return register"""
        self.util.create_ret_val_definition(socket, state, codeloc)

        return True, state

    def handle_connect(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        """
        connect = self.project.kb.functions.function(name="connect")
        cc = connect.calling_convention
        arg_atoms = self.util.create_arg_atoms(cc)

        """1. add use of current argument definitions"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        """2. ret"""
        self.util.create_ret_val_definition(connect, state, codeloc)
        return True, state

    #
    # memory allocation & management functions, i.e. malloc, free, calloc
    #
    def handle_malloc(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        void * malloc(size_t size);
        """
        malloc = self.project.kb.functions.function(name="malloc")
        arg_atoms = self.util.create_arg_atoms(malloc.calling_convention)

        rdi_atom, rdi_data, _ = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        """1. add use of args"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. allocate a HeapAddress to ret value"""
        allocated_addr = self.util.allocate(rdi_data)
        """3. create ret value"""
        dataset = DataSet()
        self.util.create_ret_val_definition(malloc, state, codeloc, )

    def handle_local_function(self, state: 'ReachingDefinitionsState', function_address: int, call_stack: List,
                              maximum_local_call_depth: int, visited_blocks: Set[int], dep_graph: 'DepGraph',
                              src_ins_addr: Optional[int] = None,
                              codeloc: Optional['CodeLocation'] = None):
        """
        Essential part for creating the inter-procedural data flow analysis, to create RDA recursively.
        """
        local_function = self.project.kb.functions.function(addr=function_address)

        # determine whether to handle a plt function
        self.handle_plt = (local_function.is_plt, function_address)

        log.info(f"ReachingDefinitionAnalysis handling local function: {local_function.name}")

        """1. get parent's rd-state & rda"""
        parent_rdstate = state
        parent_rda = self._analyses

        """2. get the function's all exit point and types, to create observation points.
              e.g. for `ret`, an observation point OP_BEFORE is needed;
                   for `call`, an observation point OP_AFTER is needed;
                   for `transition` (jump), for example @plt functions, an observation point OP_AFTER is needed.

              Moreover, for plt functions, observed_result of `OP_AFTER`s in RDA won't be
              updated after the handle_external due to the call order of `insn_observe` and `_process_block_end`
              at `engine_vex.py`, so it's necessary to manually update them.

              *:RESOLVED:*: use `node` level observe for OP_AFTER
        """
        # get all the endpoints of the function and these types
        ob_before, ob_after = [], []

        end_points = local_function.endpoints_with_type
        ret_points, trans_points, call_points = end_points["return"], end_points["transition"], end_points["call"]

        for ret_node in ret_points:
            b = local_function.get_block(ret_node.addr)
            ob_before.append(("insn", b.capstone.insns[-1].address, OP_BEFORE))   # all the return instruction address

        aset = set()
        aset.update(trans_points)
        aset.update(call_points)

        for c_t_node in aset:
            # b = local_function.get_block(c_t_node.addr)
            # ob_after.append(("insn", b.capstone.insns[-1].address, OP_AFTER))   # all the call&transition instruction address
            # use node level observe to record
            ob_after.append(("node", c_t_node.addr, OP_AFTER))

        """3. pass the parent's structures and execute child RDA,
              it's important to observe those exit points for merge
        """
        ob_points = ob_before + ob_after
        child_rda = self.project.analyses.ReachingDefinitions(
            subject=local_function,
            func_graph=local_function.graph,
            max_iterations=parent_rda._max_iterations,
            track_tmps=parent_rda._track_tmps,
            observation_points=ob_points,
            init_state=parent_rdstate,
            cc=local_function.calling_convention,
            function_handler=self,
            call_stack=parent_rda._call_stack,  # callstack <- [parent callstack] + [subject function]
            maximum_local_call_depth=parent_rda._maximum_local_call_depth,
            observe_all=parent_rda._observe_all,
            visited_blocks=parent_rda._visited_blocks,
            dep_graph=parent_rdstate.dep_graph,
            canonical_size=parent_rda._canonical_size
        )

        """3. construct the child's reaching definition state, as merging all the live_definitions at the
              local_function's exit points. (defined by step 2.)
        """

        child_rdstate = parent_rdstate
        live_defs: LiveDefinitions = child_rdstate.live_definitions
        for k in ob_points:
            result_defs = child_rda.observed_results[k]

            """
            Merge observed_results' live_definitions. For plt functions, I think, there should be only one
            observe_point, and we should use overwrite=True to take a strong replacement.
            i.e.:   read(buf1) -> read(buf1) -> here, the same buf1's definition should be at the 2nd read,
                    and the definition of buf1 at 1st read should be overwritten.
            Maybe, for those rda have only one exit point (observe point), we should take 'overwrite=True'.
            """
            overwrite = True if self.handle_plt else False
            live_defs = live_defs.merge(result_defs, overwrite=overwrite)
        child_rdstate.live_definitions = live_defs

        return True, child_rdstate, child_rda.visited_blocks, child_rda.dep_graph


    def definition_data_represent_address(self, mem_addr):
        return (
            isinstance(mem_addr, int) or
            (isinstance(mem_addr, SpOffset) and isinstance(mem_addr.offset, int)) or
            (isinstance(mem_addr, HeapAddress) and isinstance(mem_addr.value, int))
        )
