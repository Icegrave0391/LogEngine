from networkx import DiGraph

import logengine
from logengine.pt import PTParser
from logengine.audit import LogParser
from logengine.audit.beat_state import *
from logengine.audit import ProvenanceNode, ProvenanceManager, NodeType

import logging
log = logging.getLogger(__name__)

def wget_filter(beat: BeatState):
    if beat.get_process_info(ProcessInfo.exec) == "/usr/bin/wget":
        return True
    return False

if __name__ == '__main__':
    logging.getLogger(logengine.__name__).setLevel(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)
    log.setLevel(logging.DEBUG)

    log.debug(f'start pn_tester')

    logparser = LogParser()
    auditstashes = logparser.parse()

    pn_manager = ProvenanceManager(auditstashes)
    # filter wget syscall beats
    pn_manager.beat_stashes = pn_manager.filter(filter=wget_filter, filter_syscall=True)
    graph = pn_manager.construct_pn_graph(pn_manager.beat_stashes)

    print(graph)
    for n in graph.nodes:
        print(n)

    pn_manager.visualize()

