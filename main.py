import logengine
from logengine.pt import PTParser, InsnManager
from logengine.audit import LogParser
from logengine.audit import ProvenanceNode, ProvenanceManager, NodeType
from logengine.factory import ISA, ArchInfo
from logengine import Project

from logengine.cfg.cfg_utilities import CFGUtilities
from logengine.analyses.execution_flow import ExecutionFlow
from logengine.analyses.FunctionHandler.function_handler import NaiveHandler
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

    # test syscall chain
    project.construct_provenence_graph(project.proc_audit_stashes, save_name="wget")

    """
    angr embedding test
    """
    import angr
    p: angr.Project = project.create_angr_project()
    project.angr_proj = p
    """
    CFGUtilities test
    """
    project._cfg_util = CFGUtilities(p, p.factory.entry_state())
    # cfg_util.plot_full("global_cfg")

    """
    ExecutionFlow test
    """
    ef = ExecutionFlow(project)

    """
    RDA test
    """
    # should generate cfg before RDA!!
    # recover calling convention
    #_ = p.analyses.CompleteCallingConventions(recover_variables=True)
    _ = p.analyses.CompleteCallingConventions()

    from angr.analyses.reaching_definitions.function_handler import FunctionHandler
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
    from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
    from angr.procedures.definitions.glibc import _libc_decls
    from angr.analyses.reaching_definitions.dep_graph import DepGraph
    from angr.knowledge_plugins.key_definitions.atoms import Atom
    from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER

    ob_func1 = p.kb.functions.function(name='userlevel_read_file')
    ob_point1 = ('insn', ob_func1, OP_BEFORE)
    ob_func2 = p.kb.functions.function(name='fgets')
    ob_point2 = ('insn', ob_func2, OP_AFTER)

    ob_func3 = p.kb.functions.function(name='fputs')
    ob_point3 = ('insn', ob_func3, OP_AFTER)

    main_function = p.kb.functions.function(name='main')
    gethttp = p.kb.functions.function(name='gethttp')

    prda = p.analyses.ReachingDefinitions(subject=main_function,
                                          func_graph=main_function.graph,
                                          cc=main_function.calling_convention,
                                          function_handler=NaiveHandler(),
                                          call_stack=[],
                                          observation_points=[ob_point1, ob_point2, ob_point3],
                                          maximum_local_call_depth=100,
                                          dep_graph=DepGraph())

    import IPython; IPython.embed()

