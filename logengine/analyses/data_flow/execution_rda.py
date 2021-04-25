from ..execution_visitor import ExecutionGraphVisitor

from typing import Optional, DefaultDict, Dict, List, Tuple, Set, Any, Union, TYPE_CHECKING

from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
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
                 func_graph=None,
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
                                               func_graph,
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

        # check
        if not len(successors) == 1:
            raise ValueError(f"ExecutionGraphVisitor should only return 1 successor. Check it's successors!")

        succ = successors[0]
        for succ in successors:
            if succ in self._state_map:
                to_merge = [ self._state_map[succ], input_state ]
                r = self._merge_states(succ, *to_merge)
                if type(r) is tuple and len(r) == 2:
                    merged_state, reached_fixedpoint = r
                else:
                    # compatibility concerns
                    merged_state, reached_fixedpoint = r, False
                self._state_map[succ] = merged_state
            else:
                self._state_map[succ] = input_state
                reached_fixedpoint = False

            if not reached_fixedpoint:
                successors_to_visit.add(succ)

        return successors_to_visit

    def _merge_states(self, node, *states):
        def fake_merge_state(state: ReachingDefinitionsState, *others):
            copy_state = state.copy()
            for other in others:
                other: ReachingDefinitionsState
                copy_state.live_definitions = copy_state.live_definitions.merge(other.live_definitions, overwrite=True)


        return states[0].merge()
