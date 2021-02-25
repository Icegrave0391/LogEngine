import logging
from dataclasses import dataclass

import keystone as _keystone
import capstone as _capstone

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

@dataclass
class ArchInfo:
    cs_arch = _capstone.CS_ARCH_X86
    cs_mode = _capstone.CS_MODE_64
    ks_arch = _keystone.KS_ARCH_X86
    ks_mode = _keystone.KS_MODE_64

# class syscall_table

class ISA:
    """
    A collection of information about a given archtecture-ISA.
    """
    def __init__(self, arch: ArchInfo):
        self.arch = arch
        self._cs = None
        self._ks = None

    @property
    def capstone(self):
        if self.arch.cs_arch is None:
            raise TypeError(f"Arch {self.arch} does not support disassembly with capstone.")
        if self._cs is None:
            self._cs = _capstone.Cs(self.arch.cs_arch, self.arch.cs_mode)
            self._configure_capstone()
            self._cs.detail = True
        return self._cs

    @property
    def keystone(self):
        if self.arch.ks_arch is None:
            raise TypeError(f"Arch {self.arch} does not support assembly with keystone.")
        if self._ks is None:
            self._ks = _keystone.Ks(self.arch.ks_arch, self.arch.ks_mode)
            self._configure_keystone()
        return self._ks

    def _configure_capstone(self):
        pass

    def _configure_keystone(self):
        pass

    def disasm(self, bytestring, addr=0, thumb=False):
        """
        Disassembly the instruction represented by the code bytes via capstone
        :param bytestring:  The instruction code bytes
        :param addr:        The address at which the instruction should be disassembled
        :param thumb:       set ARM mode
        :return:            The disassembled instruction text
        """
        if thumb and not hasattr(self, "keystone_thumb"):
            log.warning("Specified thumb=True on non-ARM architecture")
            thumb = False
        cs = self.capstone_thumb if thumb else self.capstone
        return '\n'.join("%#x:\t%s %s" % (insn.address, insn.mnemonic, insn.op_str) for insn in cs.disasm(bytestring, addr))

    def asm(self, string, addr=0, as_bytes=True, thumb=False):
        """
        Compile the assembly instruction represented by string using keystone
        :param string:    The textual assembly instruction, separated by semicolons
        :param addr:      The address at which the text should be assembled, to deal with PC-relative access
        :param as_bytes:  Set to false to return a list of integers instead of a python byte string
        :param thumb:     If working with an ARM processor, set to True to assemble in thumb mode
        :return:          The assembled bytecode or the code value
        """
        if thumb and not hasattr(self, "keystone_thumb"):
            log.warning("Specified thumb=True on non-ARM architecture.")
            thumb = False
        ks = self.keystone_thumb if thumb else self.keystone # pylint: disable=no-member

        try:
            log.info(f"str:{string}, addr:{hex(addr)}")
            encoding, _ = ks.asm(string, addr, as_bytes)
        except TypeError:
            bytelist, _ = ks.asm(string, addr)
            if bytes is str:
                encoding = ''.join(chr(c) for c in bytelist)
            else:
                encoding = bytes(bytelist)

        return encoding
