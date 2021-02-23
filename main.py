import logengine
from logengine.pt import PTParser
from logengine.audit import LogParser
from logengine.audit import ProvenanceNode, ProvenanceManager, NodeType

import logging
log = logging.getLogger(__name__)


if __name__ == '__main__':
    logging.getLogger(logengine.__name__).setLevel(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)
    log.setLevel(logging.DEBUG)

    log.debug(f'start main')

    """
    audit beat parser test
    """
    ptparser = PTParser()
    logparser = LogParser()
    ptstashes = ptparser.retrieve_raw()
    auditstashes = logparser.parse()
    import IPython; IPython.embed()
