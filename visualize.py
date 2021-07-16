# first      pip install pygraphviz
#            pip install graphviz
# If ^ desn't work, then try
#            sudo apt-get install -y graphviz-dev
import graphviz
import pygraphviz as pgv
import networkx as nx
import angr
import os
import logengine
from typing import Any, Dict
from pathlib import Path
from networkx.drawing.nx_agraph import write_dot
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Parameter, Tmp
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.undefined import Undefined, UNDEFINED
from angr.engines.light import RegisterOffset, SpOffset
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions import Function

def magic_graph_print(filename, dependency_graph):
    root_dir = "LogEngine"
    file_dir = "graphs"
    abs_dir = os.path.abspath(os.path.dirname(__name__))
    abs_dir = abs_dir[: abs_dir.find(root_dir) + len(root_dir)]
    abs_dir = os.path.join(abs_dir, file_dir)
    if not os.path.exists(abs_dir):
        os.makedirs(abs_dir)

    path_and_filename = os.path.join(
        abs_dir, filename
    )

    write_dot(dependency_graph, "%s.dot" % path_and_filename)
    os.system("dot -Tpdf -o %s.pdf %s.dot" % (path_and_filename, path_and_filename))
    os.system("dot -Tsvg -o %s.svg %s.dot" % (path_and_filename, path_and_filename))


class Visualize:
    def __init__(
        self,
        proj: angr.project,
        exports: Dict[str, Any]=None,
        lp: logengine.Project=None
    ):
        self.proj: angr.Project = proj
        self.exports = exports if exports else {}
        self._root_dir = "LogEngine"
        self._file_dir = "graphs"
        self.lp = lp

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

    def draw_dep_graph(self, dep_graph:DepGraph, name=None):
        edges = dep_graph.edges
        nodes = dep_graph.nodes
        name = name if name else 'dep_graph'
        out = nx.DiGraph()

        def node(n: Definition):
            atom_repr = ""
            codeloc_repr = ""

            atom = n.atom
            if isinstance(atom, Register):
                atom_repr = "Atom: <%s>" % self.proj.arch.translate_register_name(atom.reg_offset, atom.size)
            else:
                atom_repr = atom.__repr__()

            codeloc = n.codeloc
            if codeloc.block_addr is None:
                codeloc_repr = '<%s>' % codeloc.sim_procedure

            if codeloc.stmt_idx is None:
                s = "<%s%#x(-)" % (
                    ("%#x " % codeloc.ins_addr) if codeloc.ins_addr else "",
                    codeloc.block_addr,
                )
            else:
                s = "<%s%#x[%d]" % (
                    ("%#x id=" % codeloc.ins_addr) if codeloc.ins_addr else "",
                    codeloc.block_addr,
                    codeloc.stmt_idx,
                )

            if codeloc.context is None:
                s += " contextless"
            else:
                cstr = ""
                c = codeloc.context[-1]
                addr = hex(c)
                f = self.proj.kb.functions.function(addr=c)
                if f:
                    addr += f"({f.name})"
                cstr += addr
                # for c in codeloc.context:
                #     addr = hex(c)
                #     f = self.proj.kb.functions.function(addr=c)
                #     if f:
                #         addr += f"({f.name})"
                #     addr += ','
                #     cstr += addr
                s += cstr
            ss = []
            if codeloc.info:
                for k, v in codeloc.info.items():
                    if v != tuple() and v is not None:
                        ss.append("%s=%s" % (k, v))
                if ss:
                    s += " with %s" % ", ".join(ss)
            s += ">"
            codeloc_repr = s

            return f"<Definition <{atom_repr},\nTags: {n.tags},\nCodeloc: {codeloc_repr},\nData:{n.data}>>"

        for n in nodes:
            n = node(n)
            out.add_node(n)

        for e in edges:
            u, v = e[0], e[1]
            outu, outv = node(u), node(v)
            out.add_edge(outu, outv)

        abs_dir = os.path.abspath(os.path.dirname(__name__))
        abs_dir = abs_dir[: abs_dir.find(self._root_dir) + len(self._root_dir)]
        abs_dir = os.path.join(abs_dir, self._file_dir)
        if not os.path.exists(abs_dir):
            os.makedirs(abs_dir)
        drop = os.path.join(abs_dir, name)
        nx.drawing.nx_agraph.write_dot(out, drop + '.dot')
        G = pgv.AGraph(drop + '.dot')
        G.draw(drop + '.png', prog='dot')
        G.draw(drop + '.pdf', prog='dot')

    def draw_funcgraph(self, function:Function, filename):
        """
        Draw the graph and save it to a PNG file.
        """
        import matplotlib.pyplot as pyplot  # pylint: disable=import-error
        from networkx.drawing.nx_agraph import graphviz_layout  # pylint: disable=import-error

        def node(n: BlockNode):
            blk = self.proj.factory.block(n.addr)
            lpblk = self.lp.blockrailset.get_block(n.addr)
            addr = hex(n.addr)
            insn_s = ""
            for insn in blk.capstone.insns:
                insn_desp = "%#x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str)
                insn_s = (insn_s + insn_desp + '\n')
            sym = lpblk.symbol if lpblk is not None else function.name
            return "<"+addr + " " + sym+">" + "\n" + insn_s

        tmp_graph = nx.DiGraph()
        for from_block, to_block in function.transition_graph.edges():
            node_a, node_b = node(from_block), node(to_block)
            tmp_graph.add_edge(node_a, node_b)
        # pos = graphviz_layout(tmp_graph, prog='fdp')   # pylint: disable=no-member
        abs_dir = os.path.abspath(os.path.dirname(__name__))
        abs_dir = abs_dir[: abs_dir.find(self._root_dir) + len(self._root_dir)]
        abs_dir = os.path.join(abs_dir, self._file_dir)
        if not os.path.exists(abs_dir):
            os.makedirs(abs_dir)
        drop = os.path.join(abs_dir, filename)
        nx.drawing.nx_agraph.write_dot(tmp_graph, drop + '.dot')
        G = pgv.AGraph(drop + '.dot')
        G.draw(drop + '.png', prog='dot')
        G.draw(drop + '.pdf', prog='dot')

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
                second = str(edge[1])
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
