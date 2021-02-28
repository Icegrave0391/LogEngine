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

    @property
    def is_syscall(self):
        last_insn = self.capstone.insns[-1]
        """
        syscall type
        """
        if last_insn.mnemonic == "syscall":
            return True
        return False

    def block_def_use(self):
        """
        Find the block def-use chain (check all the instructions of register reads and writes)
        and take do a reverse for instructions in the block (we do a backwards traversal).
        :return: Reversed order of Tuple(address, defining values, reg_written) of instructions in the block
        """
        def_use = []
        for capinsn in self.capstone.insns:
            insn = capinsn.insn
            regs_read, regs_write = insn.regs_access()
            # registers being writen
            rws = []
            for reg_num in regs_write:
                rws.append(insn.reg_name(reg_num))

            # values should be used / defined
            defining_vals = []
            if regs_read:
                # eg: mov eax, ebx ;  mov eax, dword ptr [ebx+0x1]; which means ebx should be defining value
                for reg_num in regs_read:
                    defining_vals.append(insn.reg_name(reg_num))
            else:
                # eg: mov eax, dword ptr [0x1]; no registers read.
                # which means only [0x1] of the instruction should be defining value
                val = [insn.disp]
                defining_vals.append(val)
            def_use.append((insn.address, defining_vals, rws))

        def_use.reverse()
        return def_use


class CapstoneBlock:
    __slots__ = ['addr', 'insns']

    def __init__(self, addr, insns):
        self.addr = addr
        self.insns = insns

    def pp(self):
        print(str(self))

    def get_insn(self, addr, insns):
        """
        get instruction (type CsInsn) from the address
        """
        for idx, capinsn in enumerate(insns):
            if capinsn.insn.address == addr:
                return idx, capinsn.insn
        return None, None

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
        return f"<CapstoneInsn {self.mnemonic} {self.op_str} for {hex(self.address)}>"
