import re
from .insn_state import InsnState
from .ptparser import PTParser

# perf record -e intel_pt//u --filter 'stoptrace * @ /lib/x86_64-linux-gnu/ld-2.27.so' wget www.baidu.com
# perf script --itrace=cri0ns -F+flags,+insn,+ip,+pid,+tid,+sym | xed -F insn: -64 > pt_wget
