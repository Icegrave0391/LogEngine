from typing import List, Set, Optional, TYPE_CHECKING, Union, Iterable, Dict
import logging
from visualize import magic_graph_print as mgp
log = logging.getLogger(__name__)

from ..execution_flow import ExecutionFlow

import angr

from angr.calling_conventions import SimCC
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.definition import Definition
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
        :return:       atom,
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


    def create_memory_definition(self, mem_addr_data: Iterable,
                                 mem_sz_data: Optional[Iterable],
                                 state: 'ReachingDefinitionsState',
                                 codeloc: 'CodeLocation',
                                 function: Optional[Function]):
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
        for mem_addr in mem_addr_data:
            if type(mem_addr) is Undefined:
                log.info('Memory address undefined, ins_addr = %#x.', codeloc.ins_addr)
            else:
                if self.definition_data_represent_address(mem_addr):
                    # handle a resolvable address
                    ## get the maximum size
                    max_sz = 1
                    if mem_sz_data is not None:
                        for mem_sz in mem_sz_data:
                            if isinstance(mem_sz, int) and mem_sz > max_sz:
                                max_sz = mem_sz

                    tags = {ParameterTag(function=function.addr, metadata={'tagged_by': function.name,
                                                                        'mem_addr': mem_addr,
                                                                        'mem_sz': max_sz
                                                                        })}
                    memloc = MemoryLocation(mem_addr, max_sz)
                    # add definitions
                    state.kill_and_add_definition(memloc, codeloc, UNDEFINED, tags=tags)

    def create_ret_atom(self, cc: SimCC) -> Register:
        """
        Create a return register atom, conducted by the function's cc
        """
        ret_reg = cc.return_val
        return Atom.from_argument(ret_reg, self.project.arch.registers)


class NaiveHandler(FunctionHandler):
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

    def handle_dcgettext(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        char * dcgettext (const char * domainname, const char * msgid, int category);
        """
        dcgettext = self.project.kb.functions.function(name="dcgettext")
        cc = dcgettext.calling_convention

        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)
        # add use for arguments
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        # add definition of ret
        return True, state

    def handle_strlen(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        size_t strlen(const char *s);
        """

        strlen = self.project.kb.functions.function(name="strlen")
        cc = strlen.calling_convention

        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)
        """1. add use"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)
        """2. add ret"""
        import IPython; IPython.embed()

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

    def handle_fgets(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        fgets(char * buffer, int size, FILE * stream) // rdi, rsi, rdx
        """
        fgets = self.project.kb.functions.function(name='fgets')
        cc = fgets.calling_convention

        arg_atoms: List[Register] = self.util.create_arg_atoms(cc)

        """prototype - preparation"""
        # get all the current live_definitions relative to rdi
        rdi_atom, rdi_data, rdi_current_defs = self.util.get_defs_by_register_atom(arg_atoms, 0, state, codeloc)
        rsi_atom, rsi_data, rdi_current_defs = self.util.get_defs_by_register_atom(arg_atoms, 1, state, codeloc)
        # rdi_data, rdi_atom = set(), arg_atoms[0]
        # rdi_current_defs: Iterable[Definition] = state.register_definitions.get_objects_by_offset(rdi_atom.reg_offset)
        # # get all the current live_definitions relative to rsi
        # rsi_data, rsi_atom = set(), arg_atoms[1]
        # rsi_current_defs: Iterable[Definition] = state.register_definitions.get_objects_by_offset(rsi_atom.reg_offset)
        # # get all defined data
        # for rdi_def in rdi_current_defs:
        #     rdi_data.update(rdi_def.data)
        # if len(rdi_data) == 0:
        #     rdi_data.add(UNDEFINED)
        #     state.kill_and_add_definition(rdi_atom, codeloc, rdi_data)
        #
        # for rsi_def in rsi_current_defs:
        #     rsi_data.update(rsi_def.data)
        # if len(rsi_data) == 0:
        #     rsi_data.add(UNDEFINED)
        #     state.kill_and_add_definition(rsi_atom, codeloc, rsi_data)

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
        # for mem_addr in rdi_data:
        #     if type(mem_addr) is Undefined:
        #         log.info('Memory address undefined, ins_addr = %#x.', codeloc.ins_addr)
        #     else:
        #         if self.definition_data_represent_address(mem_addr):
        #             # handle a resolvable address
        #             ## get the maximum size
        #             max_sz = 1
        #             for mem_sz in rsi_data:
        #                 if isinstance(mem_sz, int):
        #                     if mem_sz > max_sz:
        #                         max_sz = mem_sz
        #
        #             tags = {ParameterTag(function=fgets.addr, metadata={'tagged_by': fgets.name,
        #                                                                 'mem_addr': mem_addr,
        #                                                                 'mem_sz': max_sz
        #                                                                 })}
        #             memloc = MemoryLocation(mem_addr, max_sz)
        #             # add definitions
        #             state.kill_and_add_definition(memloc, codeloc, UNDEFINED, tags=tags)
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
        tags = {ReturnValueTag(write.addr, metadata={"tagged_by": "write"})}
        rax_atom = self.util.create_ret_atom(cc)
        state.kill_and_add_definition(rax_atom, codeloc, UNDEFINED, tags=tags)
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
        rax_atom = self.util.create_ret_atom(cc)
        tags = {ReturnValueTag(socket.addr, metadata={"tagged_by": "socket"})}
        state.kill_and_add_definition(rax_atom, codeloc, UNDEFINED, tags=tags)

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
        rax_atom = self.util.create_ret_atom(cc)
        tags = {ReturnValueTag(connect.addr, metadata={"tagged_by": "socket"})}
        state.kill_and_add_definition(rax_atom, codeloc, UNDEFINED, tags=tags)

        return True, state


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
