from ..execution_visitor import ExecutionGraphVisitor

from typing import Optional, DefaultDict, Dict, List, Tuple, Set, Any, Union, TYPE_CHECKING

from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from ..execution_flow import ExecutionFlow
import angr
import ailment
import pyvex
from networkx import DiGraph
from angr.analyses.reaching_definitions.subject import Subject
from angr.factory import Block
from angr.knowledge_plugins.functions import Function

if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.dep_graph import DepGraph
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState

from collections import defaultdict
import logging
log = logging.getLogger(name=__name__)



class ExecutionFlowRDA(ReachingDefinitionsAnalysis):

    def __init__(self, start_function: Function, execution_flow_graph: DiGraph,  sequence_node_map=None,
                 subject: Union[Subject, ailment.Block, Block, Function] = None,
                 max_iterations=1000,
                 track_tmps=False, observation_points=None, init_state: ReachingDefinitionsState = None, cc=None,
                 function_handler=None, call_stack: Optional[List[int]] = None, maximum_local_call_depth=1000,
                 observe_all=False, visited_blocks=None, dep_graph: Optional['DepGraph'] = None, observe_callback=None,
                 canonical_size=8
                 ):

        if subject is None or not isinstance(subject, Subject):
            subject = Subject(start_function, execution_flow_graph, start_function.calling_convention)

        subject._visitor = ExecutionGraphVisitor(execution_flow_graph, sequence_node_map=sequence_node_map)
        self._graph_visitor: ExecutionGraphVisitor = subject._visitor

        super(ExecutionFlowRDA, self).__init__(subject,
                                               execution_flow_graph,
                                               max_iterations,
                                               track_tmps,
                                               observation_points,
                                               init_state,
                                               cc,
                                               function_handler,
                                               call_stack,
                                               maximum_local_call_depth,
                                               observe_all,
                                               visited_blocks,
                                               dep_graph,
                                               observe_callback,
                                               canonical_size
                                               )

    @property
    def observed_results(self) -> Dict[Tuple[str, int, int], List[LiveDefinitions]]:
        return self.model.observed_results

    def _add_input_state(self, node, input_state):
        """
        Add the input state to all successors of the given node.
        For the execution flow, there should be only one successor for the given node, whose
        input state should strictly be the outout state of the node we passed as parameter.

        :param node:        The node whose successor's input states will be touched.
        :param input_state: The state that will be added to the successor of the node, and
                            successor's input_state should be the node's output state here.
        :return:            None
        """
        successors = self._graph_visitor.successors(node)
        successors_to_visit = set()  # a collection of successors whose input states did not reach a fixed point
        if not len(successors):
            return successors_to_visit
        # sanity check, since there should always be only successor of a node in execution flow
        elif len(successors) > 1:
            raise ValueError(f"ExecutionGraphVisitor should only return no more than 1 successor. Check it's successors!")
        succ = successors[0]

        # just abort the _state_map and use the node's output state as the succ's input state
        self._state_map[succ] = input_state
        # reached_fixedpoint = False

        # if succ in self._state_map:
        #     to_merge = [self._state_map[succ], input_state]
        #     r = self._merge_states(succ, *to_merge)
        #     if type(r) is tuple and len(r) == 2:
        #         merged_state, reached_fixedpoint = r
        #     else:
        #         # compatibility concerns
        #         merged_state, reached_fixedpoint = r, False
        #     self._state_map[succ] = merged_state
        # else:
        #     self._state_map[succ] = input_state
        #     reached_fixedpoint = False

        # if not reached_fixedpoint:
        #     successors_to_visit.add(succ)
        successors_to_visit.add(succ)
        return successors_to_visit

    def _merge_states(self, node, *states):
        """
        A Hack-ey way to merge state, at a forced way to update the input state as the new version.
        (We do not 'merge' it here, we actually 'replace' it.)
        """
        if not len(states) == 2:
            raise ValueError(f"Merge at execution flow should operate for only two states. Check _add_input_state!")

        def force_merge_state(state: ReachingDefinitionsState, other: ReachingDefinitionsState):
            state = state.copy()
            state.live_definitions = state.live_definitions.merge(other.live_definitions, overwrite=True)
            state._environment = state._environment.merge(other._environment)
            return state

        return force_merge_state(states[0], states[1])

    def node_observe(self, node_addr: int, state: ReachingDefinitionsState, op_type: int) -> None:
        """
        :param node_addr:   Address of the node.
        :param state:       The analysis state.
        :param op_type:     Type of the observation point. Must be one of the following: OP_BEFORE, OP_AFTER.
        """

        key = 'node', node_addr, op_type

        observe = False

        if self._observe_all:
            observe = True
        elif self._observation_points is not None and key in self._observation_points:
            observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback('node', addr=node_addr, state=state, op_type=op_type)

        if observe:
            self._update_observed_livedefs(key, state)

    def insn_observe(self, insn_addr: int, stmt: Union[ailment.Stmt.Statement,pyvex.stmt.IRStmt],
                     block: Union[Block,ailment.Block], state: ReachingDefinitionsState, op_type: int) -> None:
        """
        :param insn_addr:   Address of the instruction.
        :param stmt:        The statement.
        :param block:       The current block.
        :param state:       The abstract analysis state.
        :param op_type:     Type of the observation point. Must be one of the following: OP_BEORE, OP_AFTER.
        """

        key = 'insn', insn_addr, op_type
        observe = False

        if self._observe_all:
            observe = True
        elif self._observation_points is not None and key in self._observation_points:
            observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback('insn', addr=insn_addr, stmt=stmt, block=block, state=state,
                                             op_type=op_type)

        if not observe:
            return

        if isinstance(stmt, pyvex.stmt.IRStmt):
            # it's an angr block
            vex_block = block.vex
            # OP_BEFORE: stmt has to be IMark
            if op_type == OP_BEFORE and type(stmt) is pyvex.stmt.IMark:
                self._update_observed_livedefs(key, state)
            # OP_AFTER: stmt has to be last stmt of block or next stmt has to be IMark
            elif op_type == OP_AFTER:
                idx = vex_block.statements.index(stmt)
                if idx == len(vex_block.statements) - 1 or type(
                        vex_block.statements[idx + 1]) is pyvex.IRStmt.IMark:
                    self._update_observed_livedefs(key, state)
        elif isinstance(stmt, ailment.Stmt.Statement):
            # it's an AIL block
            self.observed_results[key] = [state.live_definitions.copy()]

    def _update_observed_livedefs(self, key, state):
        if key in self.observed_results.keys():
            self.observed_results[key] = self.observed_results[key] + [state.live_definitions.copy()]
        else:
            self.observed_results[key] = [state.live_definitions.copy()]
