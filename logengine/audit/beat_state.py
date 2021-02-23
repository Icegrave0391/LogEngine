from enum import Enum
from typing import List, Optional, Dict, Union
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class AuditType:
    """
    auditd type, see at:
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types
    """
    # TODO(): support more requisite audit-types
    syscall = "syscall"
    config_change = "config_change"
    service_start = "service_start"
    service_stop = "service_stop"
    user_auth = "user_auth"
    user_acct = "user_acct"
    cred_acq = "cred_acq"

class ProcessInfo:
    """
    Certain fields of process in the auditbeat process data
    """
    exec = "executable"
    pid = "pid"
    ppid = "ppid"
    name = "name"
    working_dir = "working_directory"
    args = "args"

class SyscallInfo:
    """
    Certain fields of syscall-type data in auditbeat.auditd.data
    """
    exit = "exit"
    a0 = "a0"
    a1 = "a1"
    a2 = "a2"
    a3 = "a3"
    syscall = "syscall"
    arch = "arch"
    tty = "tty"
    socket = "socket"

class SocketInfo:
    port = "port"
    addr = "addr"
    path = "path"
    saddr = "saddr"
    family = "family"

class FileInfo:
    path = "path"
    mode = "mode"

class PathsInfo:
    name = "name"


class Auditd(object):
    def __init__(self,
                 paths: Union[None, List[Dict]],
                 message_type: str,
                 sequence: int,
                 result: str,
                 data: Dict,
                 session: Union[str, None]):
        self.paths = paths if paths is not None else None
        self.msg_type = message_type
        self.result = result
        self.data = data
        self.session = session if session else None
        self.sequence = sequence

    def __repr__(self):
        return f"<Auditd sequence: {self.sequence}, type: {self.msg_type}>"

    @property
    def is_type_syscall(self) -> bool:
        if self.msg_type == AuditType.syscall:
            return True
        else:
            return False

    @property
    def syscall_name(self) -> str:
        if not self.is_type_syscall:
            raise AttributeError(f"{self.__repr__()} is not a syscall type unit.")
        return self.data["syscall"]

    @property
    def syscall_info(self) -> Dict:
        if not self.is_type_syscall:
            raise AttributeError(f'{self.__repr__()} is not a syscall type unit.')
        return self.data

    def get_syscall_info(self, field):
        try:
            info = self.syscall_info[field]
        except KeyError:
            info = None
            log.info(f"{self.__repr__()} does not have syscall field {field}.")
        return info

    # TODO(): support other type rather than syscall

class BeatState(object):
    def __init__(self, timestamp: str, process: Union[Dict, None], file: Union[Dict, None], auditd: Auditd):
        self.timestamp = timestamp
        self.process = process if process is not None else None
        self.file = file if file is not None else None
        self.auditd = auditd
        self.sequence = self.auditd.sequence

    def __repr__(self):
        exec = self.executable
        if not self.is_type_syscall:
            return f"<BeatState sequence: {self.sequence}, " \
                   f"executable: {exec}, " \
                   f"type: {self.auditd.msg_type}>"
        else:
            return f"<BeatState sequence: {self.sequence}, " \
                   f"executable: {exec}, " \
                   f"type: {self.auditd.msg_type}, " \
                   f"syscall: {self.syscall_name}>"

    @property
    def executable(self):
        if not self.process:
            return None
        try:
            exec = self.process[ProcessInfo.exec]
        except KeyError:
            exec = None
        return exec

    @property
    def is_type_syscall(self):
        return self.auditd.is_type_syscall

    @property
    def syscall_name(self):
        return self.auditd.syscall_name

    @property
    def result(self):
        if self.auditd.result == "success":
            return True
        return False

    @property
    def has_socket(self):
        return SyscallInfo.socket in self.auditd.syscall_info.keys()

    def get_syscall_info(self, field):
        return self.auditd.get_syscall_info(field)

    def get_socket_info(self, field):
        sock = self.get_syscall_info(SyscallInfo.socket)
        try:
            info = sock[field]
        except (KeyError, TypeError) as e:
            if type(e) is TypeError:
                log.info(f"{self.__repr__()} doesn't have process info.")
                info = None
            else:
                if field == SocketInfo.addr and SocketInfo.path in sock.keys():
                    info = sock[SocketInfo.path]
                elif field == SocketInfo.addr and SocketInfo.saddr in sock.keys():
                    info = sock[SocketInfo.saddr]
                else:
                    log.info(f"{self.__repr__()} doesn't have process field {field}")
                    info = None
        return info

    def get_process_info(self, field):
        try:
            info = self.process[field]
        except (KeyError, TypeError) as e:
            if type(e) is TypeError:
                log.info(f"{self.__repr__()} doesn't have process info.")
            else:
                log.info(f"{self.__repr__()} doesn't have process field {field}")
            info = None
        return info

    def get_file_info(self, field):
        try:
            info = self.file[field]
        except (KeyError, TypeError) as e:
            if type(e) is TypeError:
                log.info(f"{self.__repr__()} doesn't have file info.")
            else:
                log.info(f"{self.__repr__()} doesn't have field field {field}")
            info = None
        return info

    def get_paths_info(self, idx, field):
        if self.auditd.paths is None:
            return None
        try:
            info = self.auditd.paths[idx][field]
        except KeyError:
            log.info(f"{self.__repr__()} doesn't have paths field {field}.")
            info = None
        return info

if __name__ == "__main__":
    # tester
    data = {
            "a0": "7f0a21020d60",
            "a2": "7f0a21020168",
            "a1": "80000",
            "arch": "x86_64",
            "a3": "6f732e6572637062",
            "tty": "pts4",
            "exit": "3",
            "syscall": "open"
        }
    aud = Auditd([], "syscall", 1, "success", data, "")
    print(aud.syscall_name)
    print(aud.get_syscall_info(SyscallInfo.a1))

