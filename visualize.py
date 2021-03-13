# first      pip install pygraphviz
#            pip install graphviz
# If ^ desn't work, then try
#            sudo apt-get install -y graphviz-dev
import graphviz
import pygraphviz as pgv
import networkx as nx
import angr
import os
from typing import Any, Dict
from pathlib import Path


class Visualize:
    def __init__(
        self,
        proj: angr.project,
        exports: Dict[str, Any]
    ):
        self.proj = proj
        self.exports = exports

    def drawcfg(self, graph, start=None, end=None, name=None):

        name = name if name else 'cfg'
        out = nx.DiGraph()
        try:
            edges = graph.graph.edges
            nodes = graph.graph.nodes
        except BaseException:
            edges = graph.edges
            nodes = graph.nodes

        EDGES = list(set([(hex(edge[0].addr), hex(edge[1].addr)) for edge in edges]))
        NODES = list(set([hex(node.addr) for node in nodes]))

        for NODE in NODES:
            if int(NODE,16) == end:
                out.add_node(NODE, color='red', style='filled', fillcolor='red')
            elif int(NODE,16) == start:
                out.add_node(NODE, color='green', style='filled', fillcolor='green')
            elif int(NODE, 16) in self.exports.keys():
                NODE = self.exports[int(NODE,16)]
                out.add_node(NODE, color='yellow', style='filled', fillcolor='yellow')
            else:
                out.add_node(NODE)

        for EDGE in EDGES:
            if int(EDGE[0],16) in self.exports.keys():
                edge_z = self.exports[int(EDGE[0],16)]
            else:
                edge_z = EDGE[0]

            if int(EDGE[1],16) in self.exports.keys():
                edge_o = self.exports[int(EDGE[1],16)]
            else:
                edge_o = EDGE[1]
            out.add_edge(edge_z, edge_o)

        drop = os.path.join(Path(__file__).parent.absolute(), 'graphs/'+name)
        # Save the graph in .dot format
        nx.drawing.nx_agraph.write_dot(out, drop + '.dot')
        G = pgv.AGraph(drop + '.dot') # Read in the .dot graph
        G.draw(drop + '.png', prog='dot')  # Save the dot as a .png




    def drawddg(self, ddg, name=None):

        name = name if name else 'ddg'
        EDGES = []
        edges = ddg.graph.edges
        for edge in edges:
            fir = (str(edge[0])[0:9])
            sec = (str(edge[1])[0:9])
            if fir == "<<SimProc":
                first = str(edge[0])
            else:
                first = fir + '>'

            if sec == "<<SimProc":
                str(edge[1])
            else:
                second = sec + '>'

            if first == second:
                pass
            else:
                EDGE = (first, second)

                if EDGE not in EDGES:
                    EDGES.append(EDGE)

        NODES = []
        nodes = ddg.graph.nodes
        for node in nodes:
            sta = ((str(node))[0:9])
            if sta == "<<SimProc":
                NODE = str(node)
            else:
                NODE = sta + '>'

            if NODE not in NODES:
                NODES.append(NODE)

        DDG = nx.DiGraph()

        for NODE in NODES:
            DDG.add_node(NODE)
        for EDGE in EDGES:
            DDG.add_edge(EDGE[0], EDGE[1])

        drop = os.path.join(Path(__file__).parent.absolute(), 'graphs/'+name)
        nx.drawing.nx_agraph.write_dot(DDG, drop + '.dot')
        G = pgv.AGraph(drop +  '.dot')
        G.draw(drop + '.png', prog='dot')
