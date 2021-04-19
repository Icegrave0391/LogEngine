from typing import List, Set, Optional, TYPE_CHECKING, Union, Iterable, Dict, Tuple
import logging
log = logging.getLogger(__name__)

import angr

from angr.calling_conventions import SimCC
from angr.analyses.reaching_definitions.heap_allocator import HeapAllocator
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.unknown_size import UnknownSize, UNKNOWN_SIZE
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag, ParameterTag, ReturnValueTag, Tag
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Parameter, Tmp
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
            log.info(f"[kill_memory_definition] Memory address all undefined, function: {function.name}, codeloc: {codeloc}")
            return

        for mem_addr in mem_addr_data:

            if not self.definition_data_represent_address(mem_addr):
                log.info(f"[kill_memory_definition] Has undefined memory address, function: {function.name}, codeloc: {codeloc}")
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
        Add the memory dependency (add use of a memory location) for a reaching_definition state.
        :param mem_addr_data: a set of data which could potentially represent the memory location address
        :param default_content: when there is no such memory location definitions represented by mem_addr,
                                create that definition using that default_content(UNDEFINED) to fill the memory location.
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
        return heap_addr, memloc.size

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

