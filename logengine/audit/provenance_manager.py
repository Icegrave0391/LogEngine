from enum import Enum
from typing import List, Optional, Tuple
from networkx import MultiDiGraph

from .base_manager import ManagerBase
from .beat_state import *

class NodeType:
    process = 1
    file = 2


class ProvenanceNode:
    def __init__(self, type, fd: Optional=None, fpath: Optional=None,
                 pid:Optional=None, exec:Optional=None, args:Optional=None,
                 fd_active=True):
        self.type = type
        self.fd = fd if fd else None
        self.fpath = fpath if fpath else None
        self.pid = pid if pid else None
        self.exec = exec if exec else None
        self.args = args if args else None
        self.fd_active = fd_active

    def __eq__(self, other):
        if not isinstance(other, ProvenanceNode) or self.type != other.type:
            return False
        if self.type == NodeType.file:
            return self.fpath == other.fpath and self.fd == other.fd and self.fd_active == other.fd_active
        if self.type == NodeType.process:
            return self.pid == other.pid and self.exec == other.exec
        else:
            # TODO(): other potential types like socket...
            return True

    def __hash__(self):
        if self.type == NodeType.file:
            return hash(self.fd) ^ hash(self.fpath) ^ hash(self.fd_active)
        else:
            return hash(self.pid) ^ hash(self.exec)

    def deactive(self):
        self.fd_active = False

class ProvenanceManager(ManagerBase):

    def __init__(self, stashes: List[BeatState]):
        super().__init__(stashes)

        self.graph = MultiDiGraph()
        self.fd_map = dict() # map current fd to the filepath

    @property
    def nodes(self):
        return self.graph.nodes

    @property
    def edges(self):
        return self.graph.edges

    def assign_fd_map(self, pid, fd, fpath):
        if not pid in self.fd_map.keys():
            self.fd_map[pid] = dict()
        if not fd in self.fd_map[pid].keys():
            self.fd_map[pid][fd] = fpath
        elif self.fd_map[pid][fd] == None:
            self.fd_map[pid][fd] = fpath
        else:
            log.error(f"Should not update fd_map to an already existed file {fd}: {self.fd_map[pid][fd]} without close that.")
            raise ValueError

    def release_fd_map(self, pid, fd):
        if not pid in self.fd_map.keys():
            return
        if not fd in self.fd_map[pid].keys():
            return
        self.fd_map[pid][fd] = None

    def get_fd_map(self, pid, fd):
        return self.fd_map[pid][fd]

    def exist_node(self, node: ProvenanceNode):
        for n in self.nodes:
            if node == n:
                return n
        return None

    def locate_fd_node(self, fd: int) -> Tuple[bool, Union[None, ProvenanceNode]]:
        """
        Locate a file descriptor to the certain file node, which is active (not closed)
        """
        for n in self.nodes:
            if not n.type == NodeType.file:
                continue
            if not n.fd_active:
                continue
            if n.fd == fd:
                return True, n
        return False, None

    def add_edge(self, u_node: ProvenanceNode, v_node: ProvenanceNode, label):
        """
        Simply add edge # TODO(): potentially need to do more thing
        """
        self.graph.add_edge(u_node, v_node, label=label)

    def syscall_analyzer(self, beat:BeatState):
        sys_name = beat.syscall_name
        # CASE
        if sys_name == "execve":
            caller_fname = beat.get_paths_info(PathsInfo.name)
            callee_exec = beat.get_process_info(ProcessInfo.exec)
            callee_pid = beat.get_process_info(ProcessInfo.pid)
            # generate node

        if sys_name == "open":
            """
            <process> open <fd>  process -> fd
            """
            caller_pid = beat.get_process_info(ProcessInfo.pid)
            caller_exec = beat.get_process_info(ProcessInfo.exec)
            u_node = ProvenanceNode(type=NodeType.process, pid=caller_pid, exec=caller_exec)
            n = self.exist_node(u_node)
            if n is not None:
                u_node = n

            callee_fpath = beat.get_file_info(FileInfo.path)
            callee_fd = beat.get_syscall_info(SyscallInfo.exit) # sys_open returns fd
            # assign fd_map
            self.assign_fd_map(caller_pid, callee_fd, callee_fpath)
            v_node = ProvenanceNode(type=NodeType.file, fpath=callee_fpath, fd=callee_fd)
            # add edge
            self.add_edge(u_node, v_node, sys_name)

        if sys_name == "close":
            """
            <process> close <fd>  //  fd -> process
            """
            close_fd = beat.get_syscall_info(SyscallInfo.a0)
            exist, u_node = self.locate_fd_node(close_fd)
            if not exist:
                log.error(f"Did not find correct node to close fd: {close_fd}, beat {beat}")
                raise TypeError
            u_node.deactive()  # fd has been closed, deactive the fd node.

            caller_pid = beat.get_process_info(ProcessInfo.pid)
            caller_exec = beat.get_process_info(ProcessInfo.exec)
            # release fd_map
            self.release_fd_map(caller_pid, close_fd)
            v_node = ProvenanceNode(type=NodeType.process, pid=caller_pid, exec=caller_exec)

            exist, n = self.exist_node(v_node)
            if exist:
                v_node = n
            # add edge
            self.add_edge(u_node, v_node, sys_name)

        if sys_name == "read":
            """
            <process> read <file> // proess - read, x times -> fd(file)
            """
            caller_pid = beat.get_process_info(ProcessInfo.pid)
            caller_exec = beat.get_process_info(ProcessInfo.exec)

            callee_fd = beat.get_syscall_info(SyscallInfo.a0)
            callee_fpath = self.get_fd_map(caller_pid, callee_fd)



