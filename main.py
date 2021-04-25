import logengine
from logengine.pt import PTParser, InsnManager
from logengine.audit import LogParser
from logengine.audit import ProvenanceNode, ProvenanceManager, NodeType
from logengine.factory import ISA, ArchInfo
from logengine import Project

from logengine.cfg.cfg_utilities import CFGUtilities
from logengine.analyses.execution_flow import ExecutionFlow
from logengine.analyses.data_flow import NaiveHandler, WgetHandler
from visualize import Visualize as V
import logging
import pickle

log = logging.getLogger(__name__)

level = logging.INFO

if __name__ == '__main__':
    logging.getLogger(logengine.__name__).setLevel(level)
    logging.basicConfig(level=level)
    log.setLevel(level)
    isa = ISA(ArchInfo())
    log.debug(f'start main')

    """
    Project test
    """
    # project = Project(exec="/usr/bin/wget", audit_parser=None, pt_parser=None,
    #                   isa_util=isa)
    ## dirty way here...
    with open("/Users/chuqiz/2021/capstone/LogEngine/database/wget.dump", "rb") as f:
        log.info(f"Loading project from local file.")
        project = pickle.load(f)

    """
    provenance graph test
    """
    # project.construct_provenence_graph(project.proc_audit_stashes, save_name="wget")

    """
    angr embedding test
    """
    # import angr
    # p: angr.Project = project.create_angr_project()
    # project.angr_proj = p
    #
    """
    CFGUtilities test
    """
    p = project.angr_proj
    project._cfg_util = CFGUtilities(p, p.factory.entry_state(), load_local=True)
    # cfg_util.plot_full("global_cfg")
    #
    # """
    # ExecutionFlow test
    # """
    # ef = ExecutionFlow(project)

    #
    # function's sub graph test
    #
    http_loop = project.angr_proj.kb.functions.function(name="http_loop")
    # sub_graph = project.ef.sub_transition_graph_for_function(6540, 11589, http_loop)
    """
    RDA test
    """
    # should generate cfg before RDA!!
    # recover calling convention
    #_ = p.analyses.CompleteCallingConventions(recover_variables=True)   # why can't recover_variables?
    _ = p.analyses.CompleteCallingConventions()
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
    from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
    from angr.procedures.definitions.glibc import _libc_decls
    from angr.analyses.reaching_definitions.dep_graph import DepGraph
    from angr.knowledge_plugins.key_definitions.atoms import Atom
    from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER

    socket = p.kb.functions.function(name='socket')
    ob_point1 = ('node', socket.addr, OP_AFTER)

    fflush = p.kb.functions.function(name='fflush')
    ob_point2 = ('node', fflush.addr, OP_BEFORE)

    main_function = p.kb.functions.function(name='main')
    gethttp = p.kb.functions.function(name='gethttp')

    """
    test hack-graph
    """
    from angr.analyses.reaching_definitions.subject import Subject
    from logengine.analyses.execution_visitor import ExecutionGraphVisitor
    # connect_to_ip = p.kb.functions.function(name="connect_to_ip") # direct caller of socket
    # subg, maps = project.ef.sub_execution_flow_graph(8109, 11589)
    #
    # subject = Subject(connect_to_ip, subg, connect_to_ip.calling_convention)
    # subject._visitor = ExecutionGraphVisitor(subg, maps)
    func = p.kb.functions.function(name="read_response_body")
    subg, maps = project.ef.sub_execution_flow_graph(10596, 11577)

    subject = Subject(func, subg, func.calling_convention)
    subject._visitor = ExecutionGraphVisitor(subg, maps)
    prda = p.analyses.ReachingDefinitions(subject=subject,
                                          func_graph=subg,
                                          cc=func.calling_convention,
                                          function_handler=WgetHandler(),
                                          call_stack=[],
                                          observation_points=[ob_point1, ob_point2],
                                          maximum_local_call_depth=1000,
                                          dep_graph=DepGraph())

    import IPython; IPython.embed()

