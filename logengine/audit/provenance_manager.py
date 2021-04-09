import re
import os
from pathlib import Path
from deprecated import deprecated
from typing import List, Optional, Tuple
from networkx import MultiDiGraph, DiGraph
import networkx as nx
import pygraphviz as pgv
import logging

from .beat_state import *
from .base_manager import ManagerBase

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
#~~~~~~SOCKET TYPES~~~~~~~#
AF_NETLINK = "netlink socket"
AF_UNIX    = "unix socket"
SOCKET     = "socket"

class NodeType:
    process = 1
    file = 2
    socket = 3

class ProvenanceNode:
    def __init__(self, type, fd: Optional=None, fpath: Optional=None,
                 pid:Optional=None, exec:Optional=None, args:Optional=None,
                 port:Optional=None, addr:Optional=None,
                 fd_active=True):
        self.type = type
        # file
        self.fd = fd if fd else None
        self.fpath = fpath if fpath else None
        # process
        self.pid = pid if pid else None
        self.exec = exec if exec else None
        self.args = args if args else None
        # socket
        self.port = port if port else None
        self.addr = addr if addr else None
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
        elif self.type == NodeType.process:
            return hash(self.pid) ^ hash(self.exec)
        else:
            return hash(self.fd) ^ hash(self.port) ^ hash(self.addr)

    def __repr__(self):
        if self.type == NodeType.file:
            return f"<PN Node Type: file, fd: {self.fd}, Path: {self.fpath}>"
        elif self.type == NodeType.process:
            return f"<PN Node Type: process, pid: {self.pid}, exec: {self.exec}>"
        else:
            if self.addr:
                return f"<PN Node Type: socket, sockfd: {self.fd} connect: <addr: {self.addr}, port: {self.port}>>"
            return f"<PN Node Type: socket, sockfd: {self.fd}>"

    def deactive(self):
        self.fd_active = False

class ProvenanceManager(ManagerBase):

    def __init__(self, stashes: List[BeatState]):
        super().__init__(stashes)

        self.graph = DiGraph()
        self.fd_map = dict() # map current fd to the filepath

    @property
    def nodes(self):
        return self.graph.nodes

    @property
    def edges(self):
        return self.graph.edges

    def assign_fd_map(self, pid, exec, fd, fpath):
        """
        Assign a fd to the file path in fd_map.
        When the process invokes syscall 'open', a file descriptor should binds to
        the file opened.
        """
        # error type
        if fd == "ENOENT":
            return
        process = hash(pid) ^ hash(exec)
        if process not in self.fd_map.keys():
            self.fd_map[process] = dict()
            self.fd_map[process]["0"] = "stdin"
            self.fd_map[process]["1"] = "stdout"
            self.fd_map[process]["2"] = "stderr"

        if fd not in self.fd_map[process].keys():
            self.fd_map[process][fd] = fpath
        else:
            self.fd_map[process][fd] = fpath

    def release_fd_map(self, pid, exec, fd):
        """
        Release a fd from the file path binding.
        When the process invokes syscall 'close', a file descriptor should be released.
        """
        process = hash(pid) ^ hash(exec)
        if process not in self.fd_map.keys():
            return
        if fd not in self.fd_map[process].keys():
            return
        self.fd_map[process][fd] = None

    def get_fd_map(self, pid, exec, fd):
        """
        Get the current fpath binding to a fd from the fd_map
        """
        process = hash(pid) ^ hash(exec)
        if process not in self.fd_map.keys():
            self.fd_map[process] = dict()
            self.fd_map[process]["0"] = "stdin"
            self.fd_map[process]["1"] = "stdout"
            self.fd_map[process]["2"] = "stderr"

        try:
            info = self.fd_map[process][fd]
        except KeyError:
            raise KeyError(f"process (pid {pid}, exec {exec}) does not have fd {fd} in map")
        return self.fd_map[process][fd]

    def sockfd_available(self, pid, exec, fd):
        """
        To get whether a fd could represent an available socket
        """
        process = hash(pid) ^ hash(exec)
        if self.fd_map[process][fd] == "socket":
            return True
        return False

    @deprecated
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
        (CURRENT)
        # it's DiGraph() so that we don't need to take care of duplicate nodes
        """
        # if u_node in self.graph and v_node in
        self.graph.add_edge(u_node, v_node, label=label)

    def syscall_analyzer(self, beat:BeatState):
        log.debug(f"current beat: {beat}")
        """
        Construct the provenance graph
        """
        sys_name = beat.syscall_name
        caller_pid = beat.get_process_info(ProcessInfo.pid)
        caller_exec = beat.get_process_info(ProcessInfo.exec)
        # CASE
        if sys_name == "execve":
            caller_fname = beat.get_paths_info(0, PathsInfo.name)
            callee_exec = beat.get_process_info(ProcessInfo.exec)
            callee_pid = beat.get_process_info(ProcessInfo.pid)
            # generate node
            return

        if sys_name == "open" or sys_name == "openat":
            """
            <process> open <fd>  assign fd map
            """
            callee_fpath = beat.get_file_info(FileInfo.path)
            callee_fd = beat.get_syscall_info(SyscallInfo.exit)  # sys_open returns fd
            # assign fd_map
            self.assign_fd_map(caller_pid, caller_exec, callee_fd, callee_fpath)
            return

        if sys_name == "close":
            """
            <process> close <fd>  //  fd -> process
            """
            close_fd = beat.get_syscall_info(SyscallInfo.a0)
            # exist, u_node = self.locate_fd_node(close_fd)
            # if not exist:
            #     log.error(f"Did not find correct node to close fd: {close_fd}, beat {beat}")
            #     raise TypeError
            # u_node.deactive()  # fd has been closed, deactive the fd node.
            # release fd_map
            self.release_fd_map(caller_pid, caller_exec, close_fd)
            # v_node = ProvenanceNode(type=NodeType.process, pid=caller_pid, exec=caller_exec)
            #
            # exist, n = self.exist_node(v_node)
            # if exist:
            #     v_node = n
            # # add edge
            # self.add_edge(u_node, v_node, sys_name)
            return

        if sys_name == "read":
            """
            <process> read <file> // process <- fd(file)
            """
            callee_fd = beat.get_syscall_info(SyscallInfo.a0)
            callee_fpath = self.get_fd_map(caller_pid, caller_exec, callee_fd)
            # add edge file -> process
            u_node = ProvenanceNode(type=NodeType.file, fd=callee_fd, fpath=callee_fpath)
            v_node = ProvenanceNode(type=NodeType.process, pid=caller_pid, exec=caller_exec)
            self.add_edge(u_node, v_node, sys_name)
            return

        if sys_name == "write":
            """
            <process> write(fd, buf, count) <file> // process -> file
            """
            callee_fd = beat.get_syscall_info(SyscallInfo.a0)
            callee_fpath = self.get_fd_map(caller_pid, caller_exec, callee_fd)

            u_node = ProvenanceNode(type=NodeType.process, pid=caller_pid, exec=caller_exec)
            v_node = ProvenanceNode(type=NodeType.file, fd=callee_fd, fpath=callee_fpath)
            self.add_edge(u_node, v_node, sys_name)
            return

        if sys_name == "socket":
            """
            <process> assign sockfd
            """
            callee_fd = beat.get_syscall_info(SyscallInfo.exit)
            domain = beat.get_syscall_info(SyscallInfo.a0)
            if int(domain) == 10: # AF_NETLINK
                self.assign_fd_map(caller_pid, caller_exec, callee_fd, AF_NETLINK)
            else:
                self.assign_fd_map(caller_pid, caller_exec, callee_fd, SOCKET)
            return

        if sys_name == "connect":
            """
            <process> send <socket fd>
            """
            u_node = ProvenanceNode(type=NodeType.process, pid=caller_pid, exec=caller_exec)
            sockfd = beat.get_syscall_info(SyscallInfo.a0)
            sockaddr = beat.get_socket_info(SocketInfo.addr)

            if not beat.result:
                # unsuccessful connect syscall (just add edge)
                v_node = ProvenanceNode(type=NodeType.socket, fd=sockfd, addr=sockaddr)
                self.add_edge(u_node, v_node, sys_name)
            else:
                sockport = beat.get_socket_info(SocketInfo.port)
                # update fd_map

                fpath = f"addr: {sockaddr}, port: {sockport}"
                self.assign_fd_map(caller_pid, caller_exec, sockfd, fpath)

                v_node = ProvenanceNode(type=NodeType.socket, fd=sockfd, addr=sockaddr, port=sockport)
                self.add_edge(u_node, v_node, sys_name)
            return

        if sys_name in ["sendmsg", "sengmmsg", "send", "sendto"]:
            """
            <process> send <socket>   // process -> socketfd
            """
            sockfd = beat.get_syscall_info(SyscallInfo.a0)
            if self.get_fd_map(caller_pid, caller_exec, sockfd) == AF_NETLINK:
                addr = beat.get_socket_info(SocketInfo.saddr)
                port = None
            else:
                addr, port = re.findall(r"addr: (.*), port: (.*)", self.get_fd_map(caller_pid, caller_exec, sockfd))[0]
            u_node = ProvenanceNode(type=NodeType.process, pid=caller_pid, exec=caller_exec)
            v_node = ProvenanceNode(type=NodeType.socket, fd=sockfd, addr=addr, port=port)
            self.add_edge(u_node, v_node, sys_name)
            return

        if sys_name in ["recv", "recvfrom", "recvmsg"]:
            """
            <process> recv <socket>   // process <- sockfd
            """
            sockfd = beat.get_syscall_info(SyscallInfo.a0)
            if self.get_fd_map(caller_pid, caller_exec, sockfd) == AF_NETLINK: # ipc
                addr = beat.get_socket_info(SocketInfo.saddr)
                port = None
            else:
                addr = beat.get_socket_info(SocketInfo.addr)
                port = beat.get_socket_info(SocketInfo.port)
                # no SocketInfo in auditd log, try to resolve by fd_map
                if addr is None and port is None:
                    addr, port = re.findall(f"addr: (.*), port: (.*)",
                                            self.get_fd_map(caller_pid, caller_exec, sockfd))[0]

            u_node = ProvenanceNode(type=NodeType.socket, fd=sockfd, addr=addr, port=port)
            v_node = ProvenanceNode(type=NodeType.process, pid=caller_pid, exec=caller_exec)
            self.add_edge(u_node, v_node, sys_name)

            return

        else:
            log.warning(f"syscall_analyzer couldn't handle syscall: {sys_name} yet.")
        pass

    def construct_pn_graph(self, stashes: List[BeatState]):
        """
        construct pn graph
        """
        for beat in stashes:
            self.syscall_analyzer(beat)
        return self.graph

    def visualize(self, name=None):

        FILE_TYPE = "fd: {0}\npath: {1}"
        PROCESS_TYPE = "exec: {0}\npid: {1}"
        SOCKET_TYPE = "sockfd: {0}\naddr: {1}\nport: {2}"

        name = name if name else 'provenance_graph'
        out = DiGraph()
        edges = self.graph.edges
        nodes = self.graph.nodes

        def node(n):
            if n.type == NodeType.file:
                outn = FILE_TYPE.format(n.fd, n.fpath)
            elif n.type == NodeType.process:
                outn = PROCESS_TYPE.format(n.exec, n.pid)
            else:
                outn = SOCKET_TYPE.format(n.fd, n.addr, n.port)
            return outn

        for n in nodes:
            outn = node(n)
            out.add_node(outn)

        for e in edges:
            u, v = e[0], e[1]
            outu, outv = node(u), node(v)
            label = edges[e]["label"]
            out.add_edge(outu, outv, label=label)

        drop = os.path.join(Path(__file__).parent.absolute(), 'graph/'+name)
        nx.drawing.nx_agraph.write_dot(out, drop+'.dot')
        G = pgv.AGraph(drop+'.dot')
        G.draw(drop+'.png', prog='dot')
        G.draw(drop + '.pdf', prog='dot')
