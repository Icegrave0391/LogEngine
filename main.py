import logengine
from logengine.pt import PTParser, InsnManager
from logengine.audit import LogParser
from logengine.audit import ProvenanceNode, ProvenanceManager, NodeType
from logengine.factory import ISA, ArchInfo
from logengine.project import Project

import logging
log = logging.getLogger(__name__)

level = logging.INFO

if __name__ == '__main__':
    logging.getLogger(logengine.__name__).setLevel(level)
    logging.basicConfig(level=level)
    log.setLevel(level)
    isa = ISA(ArchInfo())
    log.debug(f'start main')

    """
    audit beat parser test
    """
    # ptparser = PTParser()
    # logparser = LogParser()
    #
    # auditstashes = logparser.parse()
    # ptstashes = ptparser.retrieve_raw()
    #
    # insn_manager = InsnManager(ptstashes)
    # ptstashes = insn_manager.proc_start_filter("/usr/bin/wget")

    """
    Project test
    """
    project = Project(exec="/home/chuqi/capstone/toy_pt/toy", audit_parser=None, pt_parser=None,
                      isa_util=isa)
    # test syscall chain
    project.construct_provenence_graph(project.proc_audit_stashes, save_name="toy")
    import IPython; IPython.embed()

