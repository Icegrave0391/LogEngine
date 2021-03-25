from typing import List, Set, Optional, TYPE_CHECKING, Union, Iterable, Dict
import logging
from visualize import magic_graph_print as mgp
log = logging.getLogger(__name__)



import angr
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
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

class NaiveHandler(FunctionHandler):

    # g_local_live_definitions: Dict[int, LiveDefinitions] = {}

    def __init__(self):
        self._analyses = None
        # self._local_func_stack = []
        self.project: 'angr.Project' = None
        self._handle_plt = False
        self._plt_addr = None

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
        return self

    def handle_local_function(self, state: 'ReachingDefinitionsState', function_address: int, call_stack: List,
                              maximum_local_call_depth: int, visited_blocks: Set[int], dep_graph: 'DepGraph',
                              src_ins_addr: Optional[int] = None,
                              codeloc: Optional['CodeLocation'] = None):
        local_function = self.project.kb.functions.function(addr=function_address)

        # determine whether to handle a plt function
        self.handle_plt = (local_function.is_plt, function_address)
        print(f"handling local function: {local_function.name}")
        """1. get parent's rd-state & rda"""
        parent_rdstate = state
        parent_rda = self._analyses

        # import IPython; IPython.embed()
        # import ipdb; ipdb.set_trace()
        # self.push_local_func_stack(function_address)
        # self.clear_live_definitions(self.current_local_func_addr, parent_rdstate.live_definitions)

        """2. get the function's all exit point and types, to create observation points,
              e.g. for `ret`, an observation point OP_BEFORE is needed;
                   for `call`, an observation point OP_AFTER is needed;
                   for `transition` (jump), for example @plt functions, an observation point OP_AFTER is needed.
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
            b = local_function.get_block(c_t_node.addr)
            ob_after.append(("insn", b.capstone.insns[-1].address, OP_AFTER))   # all the call&transition instruction address

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

        """3. construct the child's reaching definition state, as merging all the live_definitions at the local_function's
              exit points. (defined by step 2.)
        """

        child_rdstate = parent_rdstate
        live_defs: LiveDefinitions = child_rdstate.live_definitions

        for k in ob_points:
            result_defs = child_rda.observed_results[k]
            live_defs = live_defs.merge(result_defs)

        child_rdstate.live_definitions = live_defs
        return True, child_rdstate, child_rda.visited_blocks, child_rda.dep_graph



    def handle_fopen(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        # just pass that, don't change state for right now
        print(f"[handle fopen] codeloc: {codeloc}")

        # fake test
        fake_mem_atom = MemoryLocation(0x1, 0x1)
        state.kill_and_add_definition(atom=fake_mem_atom, code_loc=codeloc, data=UNDEFINED, tags={ParameterTag(metadata="fake")})

        # plt-case
        self.update_plt_observe(state.analysis, state.live_definitions)
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

        # SimRegArg(SimFunctionArgument)
        args = cc.args

        # RegisterAtom
        arg_atoms: List[Register] = []
        for arg in args:
            arg_atoms.append(Atom.from_argument(arg, self.project.arch.registers))

        """1. add use for current definitions, indicating that the parameters have passed on"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        """2. determine the definition value, to create relevant memorylocation,
              and add definitions
        """

        # 2.1 first get all the current live_definitions relative to rdi
        rdi_data, rdi_atom = set(), arg_atoms[0]
        rdi_current_defs: Iterable[Definition] = state.register_definitions.get_objects_by_offset(rdi_atom.reg_offset)
        # get all defined data
        for rdi_def in rdi_current_defs:
            rdi_data.update(rdi_def.data)
        if len(rdi_data) == 0:
            rdi_data.add(UNDEFINED)
            state.kill_and_add_definition(rdi_atom, codeloc, rdi_data)

        # 2.2 get all the current live_definitions relative to rsi
        rsi_data, rsi_atom = set(), arg_atoms[1]
        rsi_current_defs: Iterable[Definition] = state.register_definitions.get_objects_by_offset(rsi_atom.reg_offset)
        for rsi_def in rsi_current_defs:
            rsi_data.update(rsi_def.data)
        if len(rsi_data) == 0:
            rsi_data.add(UNDEFINED)
            state.kill_and_add_definition(rsi_atom, codeloc, rsi_data)

        # 2.3 create all the certain memory locs
        for mem_addr in rdi_data:
            if type(mem_addr) is Undefined:
                log.info('Memory address undefined, ins_addr = %#x.', codeloc.ins_addr)
            else:
                if (
                    isinstance(mem_addr, int) or
                    (isinstance(mem_addr, SpOffset) and isinstance(mem_addr.offset, int)) or
                    (isinstance(mem_addr, HeapAddress) and isinstance(mem_addr.value, int))
                ):

                    # handle a resolvable address
                    ## get the maximum size
                    max_sz = 1
                    for mem_sz in rsi_data:
                        if isinstance(mem_sz, int):
                            if mem_sz > max_sz:
                                max_sz = mem_sz

                    tags = {ParameterTag(function=fgets.addr, metadata={'tagged_by': fgets.name,
                                                                        'mem_addr': mem_addr,
                                                                        'mem_sz': max_sz
                                                                        })}
                    memloc = MemoryLocation(mem_addr, max_sz)

                    # add definitions
                    state.kill_and_add_definition(memloc, codeloc, UNDEFINED, tags=tags)

        # self.update_live_definitions(self.current_local_func_addr, state.live_definitions)

        # import ipdb; ipdb.set_trace()
        return True, state



    def handle_fputs(self, state: 'ReachingDefinitionsState', codeloc: 'CodeLocation'):
        """
        fputs(char * buffer, FILE * stream) // rdi, rsi
        """
        fputs = self.project.kb.functions.function(name='fputs')
        cc = fputs.calling_convention

        # SimRegArg(SimFunctionArgument)
        args = cc.args

        # RegisterAtom
        arg_atoms: List[Register] = []
        for arg in args:
            arg_atoms.append(Atom.from_argument(arg, self.project.arch.registers))

        """1. add use for current definitions, indicating that the parameters have passed on"""
        for reg_atom in arg_atoms:
            state.add_use(reg_atom, codeloc)

        """2. determine the use-value, to add dependency
        """
        # 2.1 first get all the current live_definitions relative to rdi
        rdi_data, rdi_atom = set(), arg_atoms[0]
        rdi_current_defs: Iterable[Definition] = state.register_definitions.get_objects_by_offset(rdi_atom.reg_offset)
        # get all defined data
        for rdi_def in rdi_current_defs:
            rdi_data.update(rdi_def.data)
        if len(rdi_data) == 0:
            rdi_data.add(UNDEFINED)
            state.kill_and_add_definition(rdi_atom, codeloc, rdi_data)

        # state.memory_definitions.
        import ipdb;ipdb.set_trace()
        import IPython;IPython.embed()
