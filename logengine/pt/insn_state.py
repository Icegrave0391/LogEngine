import logging
from typing import ByteString

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class InsnState(object):
    def __init__(self, comm:str, tid:int, pid:int, cpuinfo:str, timestamp:str, insn_type:int,
                 flag:str, ip:int, sym:str, offset:int, exec:str, insn:str, **kwargs):
        if kwargs:
            log.warning("Unused keyword arguments passed to InsnState: %s", " ".join(kwargs))
        self.comm = comm
        self.tid = tid
        self.pid = pid
        self.cpuinfo = cpuinfo
        self.timestamp = timestamp
        self.insn_type = insn_type
        self.flag = flag if flag is not None else None
        self.ip = ip
        self.sym = sym if sym is not None else None
        self.offset = offset if offset is not None else None
        self.insn = insn
        self.exec = exec

    def __eq__(self, other):
        if not isinstance(other, InsnState):
            return False
        return self.ip == other.ip and self.insn_type == other.insn_type and self.insn == other.insn

    def __hash__(self):
        return hash(self.ip) ^ hash(self.insn_type) ^ hash(self.insn)

    def __repr__(self):
        type = 'instruction' if self.insn_type else 'branch'
        if self.insn_type:
            if not isinstance(self.insn, ByteString):
                return f"<InsnState ip: {hex(self.ip)}, type: {type}, insn: {self.insn}>"
            else:
                from logengine.factory import ISA, ArchInfo
                isa_util = ISA(ArchInfo())
                return f"<InsnState ip: {hex(self.ip)}, type: {type}, insn: {self.insn} ({isa_util.disasm(self.insn, self.ip)})>"
        else:
            return f"<InsnState ip: {hex(self.ip)}, type: {type}>"

    @property
    def is_syscall(self):
        if self.insn == "syscall":
            return True
        return False
