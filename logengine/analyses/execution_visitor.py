from angr.analyses.forward_analysis.visitors.graph import GraphVisitor
from angr.knowledge_plugins.functions import Function
from angr.codenode import BlockNode

from networkx import DiGraph
from collections import OrderedDict
from typing import Optional, Dict
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class ExecutionGraphVisitor(GraphVisitor):
    """
    A graph visitor takes a node in the graph and returns its successors.
    Specifically, it's a visitor for the execution flow graph, which is actually a plain list (represented in graph format).
    It will return a certain successor of a BlockNode in execution flow (distinguished by the traverse_index, also known as sequence_index).
    """
    def __init__(self, execution_graph, sequence_node_map: Optional[OrderedDict]):

        super(ExecutionGraphVisitor, self).__init__()

        self.graph: DiGraph = execution_graph

        self._sequence_node_map: OrderedDict[int, BlockNode] = sequence_node_map if sequence_node_map else None
        self._traversed_nodes_map: OrderedDict[int, BlockNode] = OrderedDict()
        self._traverse_index = None
        self._max_index = None

        self.reset()

    def successors(self, node):
        """
        Returns all successors to the specific node.
        Get successors in a tricky way, by using the traver_index to location the current node in execution flow.
        """
        self._sanity_check(node)

        if self._traverse_index == self._max_index:
            return []

        succ = self._sequence_node_map[self._traverse_index + 1]
        if succ not in self.graph.successors(node):
            raise ValueError(f"Node: {node} getting successors failed.")
        return [succ]

    def predecessors(self, node):
        """
        Returns all predecessors of the specific node.
        Get predecessors in a tricky way, by using the traver_index to location the current node in execution flow.
        """
        self._sanity_check(node)

        if self._traverse_index == 0:
            return []

        pred = self._traversed_nodes_map[self._traverse_index - 1]
        if pred not in self.graph.predecessors(node):
            raise ValueError(f"Node: {node} getting predecessors failed.")
        return [pred]

    def revisit_successors(self, node, include_self=True):
        """
        Revisit a node in the future. As a result, the successors to this node will be revisited as well.
        I think we should do nothing here.

        :param node: The node to revisit in the future.
        :return:     None
        """
        self._sanity_check(node)
        _, n = next(iter(self._sequence_node_map.items()))
        if self.successors(node)[0] != n:
            log.warning(f"revisit node {node} failed. the next item in _sequence_node_map: {n}")
        pass

    def next_node(self):
        if not len(self._sequence_node_map):
            return None
        # pop sequence_node_map to get the next node and sequence index
        self._traverse_index, node = self._sequence_node_map.popitem(last=False)
        # add to traversed map
        self._traversed_nodes_map[self._traverse_index] = node
        # manipulate the node's attribute to determine whether it has reached fixpoint
        self.graph.nodes[node]["sequences"].remove(self._traverse_index)
        if not len(self.graph.nodes[node]["sequences"]):
            self._reached_fixedpoint.add(node)

        return node

    def reached_fixedpoint(self, node):
        log.info(f"call [reached_fixedpoint]")
        pass


    def reset(self):
        self._sorted_nodes.clear()
        self._node_to_index.clear()
        self._reached_fixedpoint.clear()
        self._traversed_nodes_map.clear()

        self._traverse_index = 0
        if self._sequence_node_map is None:
            self._sequence_node_map = self._generate_sequence_node_map()
        self._max_index = len(self._sequence_node_map) - 1

    def sort_nodes(self, nodes=None):
        log.debug(f"call [sort_nodes]")
        pass

    def all_successors(self, node, skip_reached_fixedpoint=False):
        log.debug(f"call all_successors")
        pass

    def revisit_node(self, node):
        log.debug(f"call revisit_node")
        pass

    def _generate_sequence_node_map(self) :
        """
        Generate the sequence_node map from the graph.node["sequences"], which is an ordered_map.
        TODO(): Should sort the nodes via those attribute `sequences` as the keys. The values should be the nodes themselves.
        TODO(): Not implemente yet. should always use return_sequence_map=True when call `ExecutionFlow.sub_execution_flow_graph()`
        :return: OrderedDict[int, BlockNode]
        """
        raise NotImplementedError

    def _sanity_check(self, node):
        if self._traverse_index in self._traversed_nodes_map.keys():
            check_node = self._traversed_nodes_map[self._traverse_index]
        elif self._traverse_index in self._sequence_node_map.keys():
            check_node = self._sequence_node_map[self._traverse_index]
        else:
            raise KeyError(f"Node maps don't contain key: {self._traverse_index}, check the _traverse_index!")

        if node != check_node:
            log.error(f"error visiting node: {node}, for the current sequence_node_map is {self._traverse_index}: {self._sequence_node_map[self._traverse_index]}")
            raise ValueError
        pass
