import angr
from angr.knowledge_plugins.functions import Function

import logengine
from logengine.factory.block import Block
from logengine.cfg.cfg_utilities import CFGUtilities

from typing import List, Optional, Tuple, Union, Iterable, Dict
from networkx import DiGraph

import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class CallSite:
    """
    This class stands for the callsites in the execution flow graph.
    The function determines caller_function of a certain point.
    The node sequence(sequence number of the node) indicates the callsite of the caller_function.
    """
    def __init__(self, function: Function, node_sequence):
        self.caller = function
        self.callsite_sequence = node_sequence

    def __repr__(self):
        if self.caller is None:
            return f"<>"
        return f"<CallSite for caller: {self.caller.name}, callsite_sequence_index: {self.callsite_sequence}>"

class EFGNode(object):
    """
    This class stands for each single node in execution flow grpah
    """

    def __init__(self, block: Block, symbol=None, is_plt=False, func:Optional[Function]=None):
        self.block = block
        self._name = None
        self.is_plt = is_plt
        self._call_stack_dict = None
        self.function = func
        self._symbol = symbol

    @property
    def symbol(self):
        if self._symbol is None:
            self._symbol = self.block.symbol
        return self._symbol

    @property
    def addr(self):
        return self.block.addr

    @property
    def is_syscall(self):
        return self.block.is_syscall

    def __hash__(self):
        return hash(self.addr)

    def __eq__(self, other):
        if not isinstance(other, EFGNode):
            return False
        elif self.addr == other.addr:
            return True
        else:
            return False

    def __repr__(self):
        return f"<EFGNode addr: {hex(self.addr)}, function: {self.symbol}>"

class ExecutionFlow():

    def __init__(self, project: logengine.Project, keep_call_stack=True):
        self.project = project
        self.angr_project: angr.Project = project.angr_proj
        self.graph = DiGraph()

        # a function call stack to record the call_chain
        self._func_stack: List[Union[CallSite, None]]= []
        self._keep_call_stack = keep_call_stack
        self.__current_block: Union[Block, None] = None
        self.__prev_node : Union[EFGNode, None] = None
        self.__prev_block: Union[Block, None] = None

        self._analyze()

    @property
    def edges(self):
        return self.graph.edges

    @property
    def nodes(self):
        return self.graph.nodes

    def get_any_node(self, addr: Optional[int]=None, sequence_index:Optional[int]=None) -> Union[EFGNode, None]:
        """
        Get a execution flow node(EFGNode), which could be specified by either address or
        its sequence_index at execution flow
        """
        if addr is None and sequence_index is None:
            log.warning("Please indicate at least addr or sequence_index parameters.")
            return None

        for node in self.nodes:
            if addr:
                if node.addr == addr:
                    return node
            else:
                sequences = self.nodes[node]["sequences_and_caller"].keys()
                if sequence_index in sequences:
                    return node
        return None

    def get_caller_by_sequence_node(self, sequence_index: int) -> CallSite:
        """
        Get the caller info for a node, which represents the specified execution flow sequence index.
        :returns Callsite, which contains the caller function symbol, and the caller's callsite sequence index.
        """
        if sequence_index >= len(self.project.blockrailset.rail):
            raise IndexError(f"exceeded the max index for blockrailset {len(self.project.blockrailset.rail)}")

        for node in self.nodes:
            sequences_and_caller: Dict[int, CallSite] = self.nodes[node]["sequences_and_caller"]
            if sequence_index not in sequences_and_caller.keys():
                continue

            return sequences_and_caller[sequence_index]

        return None

    #
    #  private methods
    #
    def _add_edge(self, u_node, v_node, sequence_index: int):
        if not (u_node, v_node) in self.edges:
            orders = [sequence_index]
            self.graph.add_edge(u_node, v_node, orders=orders)
        else:
            self.edges[u_node, v_node]["orders"].append(sequence_index)

    def _add_node(self, node: EFGNode, sequence_index: int, direct_caller: Optional[CallSite]=None):
        if node not in self.nodes:
            sequences_and_caller = dict()
            sequences_and_caller[sequence_index] = direct_caller

            self.graph.add_node(node, sequences_and_caller=sequences_and_caller)
        else:
            self.nodes[node]["sequences_and_caller"][sequence_index] = direct_caller

    def _get_current_caller(self):
        if not len(self._func_stack):
            return None
        return self._func_stack[-1]

    def _update_call_stack(self, cs):
        self._func_stack.append(cs)

    def _pop_call_stack(self):
        if not len(self._func_stack):
            log.warning("Tried to pop the empty call_stack saved local. Failed.")
        self._func_stack.pop()

    def _analyze(self):
        """
        Construct the execution flow graph, conducted by the project's blockrailset.
        :return:
        """
        log.info(f"Start to construct execution flow graph.")
        if self.project._cfg_util is None:
            log.info(f"Initializing with angr's CFG...")
            self.project._cfg_util = CFGUtilities(self.angr_project, self.angr_project.factory.entry_state())

        block_rail_set = self.project.blockrailset
        self.graph.clear()

        sequence_order = 0

        for block_addr in block_rail_set.rail:
            # update the execution flow block location
            self.__prev_block = self.__current_block
            self.__current_block = block_rail_set.get_block(block_addr)

            # the first block in railset, do initialization
            if self.__prev_block is None:
                _start_sym = self.project.resolve_block_symbol(self.__current_block)
                _start = self.angr_project.kb.functions.function(name=_start_sym)

                # init the node
                node = EFGNode(self.__current_block, symbol=_start_sym, func=_start)
                self._add_node(node, sequence_order, direct_caller=None)
                # update prev_node
                self.__prev_node = node

            # a transition event for two nodes(basic blocks)
            else:
                curr_sym = self.project.resolve_block_symbol(self.__current_block)
                curr_func = self.angr_project.kb.functions.function(name=curr_sym)

                u_node = self.__prev_node
                v_node = EFGNode(self.__current_block, symbol=curr_sym, func=curr_func)

                # jump in the same function,
                # or during the syscall_chain,
                # or in plt to syscall
                # we treat a syscall_chain induced by a plt function (like getaddrinfo), as in a same caller function
                # func -call-> (plt -> syscall1 ->.. -> syscalln) -ret-> func
                #               ^ those direct_caller = func
                if (self.__prev_node.symbol == curr_sym or                                         # jump in the same function
                    (self.__prev_block.is_syscall and self.__current_block.is_syscall) or          # during syscall_chain
                    (self.__prev_block.plt_info()[0] is True and self.__current_block.is_syscall)  # plt jmps to syscall
                    ):

                    # get direct caller, add node, and create edge
                    direct_caller = self._get_current_caller()

                # returns from a syscall or a syscall chain,  (syscall -ret-> func)
                # or returns from plt function,               (func -call-> plt -ret-> func)
                # or returns from another function            (funcA -> funcB -> funcC -ret-> funcB)
                elif (
                    (self.__prev_block.is_syscall and not self.__current_block.is_syscall) or
                    (self.__prev_block.plt_info()[0] is True and not self.__current_block.is_syscall) or
                    self.__prev_block.is_return
                ):
                    self._pop_call_stack()
                    direct_caller = self._get_current_caller()

                # call or jump to another functionh
                else:
                    cs = CallSite(function=u_node.function, node_sequence=sequence_order-1)
                    self._update_call_stack(cs)
                    direct_caller = self._get_current_caller()

                self._add_node(v_node, sequence_order, direct_caller=direct_caller)
                self._add_edge(u_node, v_node, sequence_index=sequence_order)

                self.__prev_node = v_node
            """ update the current node sequence order index"""
            sequence_order += 1
