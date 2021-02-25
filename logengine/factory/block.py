import logging
from typing import List
from dataclasses import dataclass
from .isa import ISA, ArchInfo

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class Block:

    BLOCK_MAX_SIZE = 4096

    def __init__(self, addr, byte_string, project=None, isa_util: ISA=None, size=None, thumb=False,
                 exec=None, pid=None):

        # set up arch
        if project is not None:
            self.isa_util = project.isa_util
        else:
            self.isa_util = isa_util

        if self.isa_util is None:
            raise ValueError("Either 'project' or 'isa_util' has to be specified.")
        # properties
        self._project = project
        self.addr = addr
        self.thumb = thumb
        self.exec = exec
        self.pid = pid
        self._capstone = None

        if self._project is None and byte_string is None:
            raise ValueError("byte_string has to be specified if project is not provided.")

        if size is None:
            if byte_string is not None:
                size = len(byte_string)
        else:
            if size > len(byte_string):
                size = len(byte_string)
        self.size = size

        if type(byte_string) is bytes:
            self._bytes = byte_string[:self.size]
        else:
            self._bytes = byte_string

    def __repr__(self):
        return '<Block for pid: %s, addr %#x, %d bytes>' % (self.exec, self.addr, self.size)

    def __hash__(self):
        return hash((type(self), self.addr, self.bytes))

    def __eq__(self, other):
        if type(self) is not type(other):
            return False
        return self.addr == other.addr and \
               self.bytes == other.bytes

    def __ne__(self, other):
        return not self == other

    @property
    def bytes(self):
        return self._bytes

    @property
    def capstone(self):
        if self._capstone: return self._capstone

        cs = self.isa_util.capstone

        insns = []

        for cs_insn in cs.disasm(self.bytes, self.addr):
            insns.append(CapstoneInsn(cs_insn))
        block = CapstoneBlock(self.addr, insns)

        self._capstone = block
        return block

    @property
    def pp(self):
        return self.capstone.pp()

    # @property
    # def is_syscall(self):


class CapstoneBlock:
    __slots__ = ['addr', 'insns']

    def __init__(self, addr, insns):
        self.addr = addr
        self.insns = insns

    def pp(self):
        print(str(self))

    def __str__(self):
        return "\n".join(map(str, self.insns))

    def __repr__(self):
        return f"<CapstoneBlock for {hex(self.addr)}>"

class CapstoneInsn:
    def __init__(self, capstone_insn):
        self.insn = capstone_insn

    def __getattr__(self, item):
        if item in ('__str__', '__repr__'):
            return self.__getattribute__(item)
        if hasattr(self.insn, item):
            return getattr(self.insn, item)
        raise AttributeError()

    def __str__(self):
        return "%#x:\t%s\t%s" % (self.address, self.mnemonic, self.op_str)

    def __repr__(self):
        return f"<CapstoneInsn {self.mnemonic} for {hex(self.address)}>"
