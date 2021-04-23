import logging
import os
import pickle
from collections import deque
from typing import Any, Dict, List, Tuple, Union

import angr
import networkx as nx
from angr.analyses import CFGEmulated, CFGFast
from angr.analyses.cfg import CFGNode
from angr.analyses.cfg.indirect_jump_resolvers.jumptable import JumpTableResolver
from angr.knowledge_plugins.functions import Function

# from forsee.techniques.procedure_handler.procedure_handler import ExportManager
from angrutils import *

log = logging.getLogger(name=__name__)


class CFGUtilities:
    def __init__(
        self,
        proj: angr.Project,
        # imports: Dict[int, str],        # TODO(): THIS IS NOT FORSEE!!!
        # exports: Dict[int, str],
        entry_state: angr.sim_state,
        auto_save=True,
        load_local=False,
        root_dir="LogEngine",
        file_dir="temp",
    ):
        log.info("Generating CFGUtilities, please wait for a few minutes...")
        self.proj: angr.Project = proj
        self.state: angr.sim_state = entry_state
        self._root_dir = root_dir
        self._file_dir = file_dir
        self._cfgpath = None
        self._kbpath = None
        # self.cfg: angr.analyses.CFGEmulated = self.load() if load_local else proj.analyses.CFGEmulated(
        #     starts=[entry_state.addr], context_sensitivity_level=2,
        #     keep_state=True
        # )
        self.cfg: angr.analyses.CFGFast = self.load() if load_local else proj.analyses.CFGFast(
            normalize=True,
            data_references=True
        )
        log.debug("CFGUtilities generated!")
        if auto_save:
            self.save()

    @property
    def cfg_path(self):
        if self._cfgpath is None:
            abs_dir = os.path.abspath(os.path.dirname(__name__))
            abs_dir = abs_dir[: abs_dir.find(self._root_dir) + len(self._root_dir)]
            abs_dir = os.path.join(abs_dir, self._file_dir)
            if not os.path.exists(abs_dir):
                os.makedirs(abs_dir)
            proj_name = os.path.basename(self.proj.filename)
            self._cfgpath = os.path.join(
                abs_dir, proj_name[: proj_name.find(".")] + ".cfgmodel"
            )
        return self._cfgpath

    @property
    def kb_path(self):
        if self._kbpath is None:
            abs_dir = os.path.abspath(os.path.dirname(__name__))
            abs_dir = abs_dir[: abs_dir.find(self._root_dir) + len(self._root_dir)]
            abs_dir = os.path.join(abs_dir, self._file_dir)
            if not os.path.exists(abs_dir):
                os.makedirs(abs_dir)
            proj_name = os.path.basename(self.proj.filename)
            self._kbpath = os.path.join(
                abs_dir, proj_name[: proj_name.find(".")] + ".kb"
            )
        return self._kbpath

    def plot_full(self, name):
        abs_dir = os.path.abspath(os.path.dirname(__name__))
        abs_dir = abs_dir[: abs_dir.find(self._root_dir) + len(self._root_dir)]
        abs_dir = os.path.join(abs_dir, "graphs")
        if not os.path.exists(abs_dir):
            os.makedirs(abs_dir)
        proj_name = os.path.basename(self.proj.filename)
        if not name:
            fp = os.path.join(abs_dir, proj_name[:proj_name.find(".")])
        else:
            fp = os.path.join(abs_dir, name)
        log.info(fp)
        plot_cfg(self.cfg, fp, format="pdf", asminst=True, remove_imports=True, remove_path_terminator=True)


    def save(self):
        """
        Save CFG `model` and `kb` to the local file
        :param root_dir: project root dir name
        """
        # save cfg model to temp local file
        log.debug("Start to save files...")
        with open(self.cfg_path, "wb") as f:
            f.write(pickle.dumps(self.cfg, -1))
            print(f"CFG model saved at {self.cfg_path}")
            log.debug(f"CFG model saved at {self.cfg_path}")
        with open(self.kb_path, "wb") as f:
            f.write(pickle.dumps(self.cfg.kb, -1))
            print(f"CFG kb saved at {self.kb_path}")
            log.debug(f"CFG kb saved at {self.kb_path}")

    def load(self) -> CFGFast:
        """
        Load cfg `model` and `kb` from local files.
        """
        log.warning("Trying to recover CFG from local file.")
        try:
            f_cfg = open(self.cfg_path, "rb")
            cfg = pickle.loads(f_cfg.read())
            f_cfg.close()
        except FileNotFoundError:
            log.error(f"Path {self.cfg_path} not exists, cfg model loaded failed")
            log.warning(f"Re-constructing CFG instead.")
            return self.proj.analyses.CFGEmulated(
                starts=[self.state.addr], context_sensitivity_level=2,
                keep_state=True
            )
        try:
            f_kb = open(self.kb_path, "rb")
            kb = pickle.loads(f_kb.read())
            f_kb.close()
        except FileNotFoundError:
            log.error(f"Path {self.kb_path} not exists, knowledge_base loaded failed")
            return cfg
        cfg.kb = kb
        self.proj.kb = kb
        log.info("Recovered CFG model and knowledge_base from local successfully!")
        log.warning("Warn! Only `model` and `kb` have been recovered.")
        return cfg

    def ecfg(
        self, base_graph: nx.DiGraph(), start: int
    ) -> angr.analyses.cfg.cfg_emulated.CFGEmulated:
        return self.proj.analyses.CFGEmulated(
            keep_state=True,
            context_sensitivity_level=2,
            state_add_options=angr.options.refs,
            starts=[start],
            base_graph=base_graph,
        )

    # def :
    def ddg(
        self, ecfg: angr.analyses.cfg.cfg_emulated.CFGEmulated, start: int
    ) -> angr.analyses.ddg.DDG:
        return self.proj.analyses.DDG(ecfg, start=start)

    def cfg_imports_to_call_sites(self) -> Dict[int, str]:
        """
        Get the call_site addresses to all the imported functions contains in CFG
        :return: Dict [callsite_block_address, imported_function_name]
        """
        # Some imports are in cfg.kb.functions
        # We can convert the functions to CFG Nodes and find the node predecessors (in edge or node that called this one)
        # The last instruction of the predecessor node is the call site for the import
        # Don't ask me why It can't resolve if there is an edge
        # non subroutines - so just imports, right?
        import_funcs = [
            func
            for f_addr, func in self.cfg.kb.functions.items()
            if "sub" not in func.name
        ]
        call_site_to_cfg_function_import = {}
        for i in import_funcs:
            node = self.cfg.model.get_any_node(i.addr)
            if node:
                preds = node.predecessors
                for pred in preds:
                    if pred.addr not in call_site_to_cfg_function_import.keys():
                        call_site_to_cfg_function_import[pred.addr] = i.name
        return call_site_to_cfg_function_import

    def xrefs(self, sink_name: str) -> list:
        return [
            k for k, v in self.call_targets.items() if v.lower() == sink_name.lower()
        ]

    def xrefs_insn(self, sink_name: str) -> list:
        call_sites = self.xrefs(sink_name)
        return [
            self.proj.factory.block(cs).capstone.insns[-1].insn.address
            for cs in call_sites
        ]

    def get_block_exit(self, addr: int):
        exit_ins = None
        try:
            exit_ins = self.proj.factory.block(addr).capstone.insns[-1].insn
        except BaseException:
            return None
        return exit_ins

    def resolve(self, instruction_addr: int, jumpkind: str) -> list:
        """
        Resolves indirect jumps and calls (Ijk_boring and Ijk_Call)

        :param int addr: IRSB address.
        :param str: jumpkind ("Ijk_boring" or "Ijk_Call")
        :return: list of resolved targets
        :rtype: list
        """
        block = self.proj.factory.block(instruction_addr)
        node = self.cfg.model.get_any_node(instruction_addr, anyaddr=True)
        if not node:
            return []
        func_addr = node.function_address
        try:
            JTR = JumpTableResolver(self.proj)
            resolver = JTR.resolve(
                self.cfg, instruction_addr, func_addr, block, jumpkind
            )
            if resolver[0]:
                return resolver[1]
        except BaseException:
            return []
        return []

    def is_indirect(self, addr: int) -> tuple:
        """
        Identifies if an instruction is an indirect jump or call

        :param int addr: IRSB address.
        :param int func_addr: The function address.
        :return: tuple [bool, int]
        :rtype: tuple
        """
        out = self.get_block_exit(addr)
        if out:
            mnemonic = out.mnemonic
            if mnemonic == "call" or mnemonic.startswith("j"):
                jumpkind = "Ijk_Call" if mnemonic == "call" else "Ijk_boring"
                # if out.op_str in registers or "ptr" in out.op_str or out.disp != 0:
                if (
                    out.reg_name(out.operands[0].value.reg)
                    or "ptr" in out.op_str
                    or out.disp != 0
                ):
                    return (True, out.address, jumpkind)
        return (False, None, None)

    def paths_to_sink(self, sink) -> Dict[int, int]:

        if isinstance(sink, str):
            found = False
            for k, v in self.call_targets.items():
                if v.lower() == sink.lower():
                    found = True
                    return self.get_reachability_map(self.cfg, k)
            if not found:
                log.error(f"{sink} not found.")
                return {}
        return self.get_reachability_map(self.cfg, sink)

    def get_reachability_map(self, cfg, sink_addr) -> Dict[int, int]:
        """
        Get a map of basic block start addresses to the minimum number of steps from
        the block to the sink
        """
        reachability_map = {}
        visited = set()
        queue = deque()
        sink_nodes = cfg.model.get_all_nodes(sink_addr, anyaddr=True)
        for sink_node in sink_nodes:
            queue.append((sink_node, 0))
        while len(queue) > 0:
            node, num_steps = queue.popleft()
            if node not in visited:
                visited.add(node)
                node_addr = node.addr
                if node_addr not in reachability_map:
                    reachability_map[node_addr] = num_steps
                for predecessor in node.predecessors:
                    if predecessor not in visited:
                        queue.append((predecessor, num_steps + 1))
        return reachability_map

    def thunk(self, cfg: CFGEmulated, func: Function) -> bool:
        """
        Checks a function for 'thunkness'. I've observed that a thunk function
        has one call site and that call site address is equal to the thunk function
        address

        Parameter:
                func: function object (angr.knowledge_plugins.functions.function.Function)

        Returns:
                bool: True or False (Thunk or Not)
        """
        # If it's a thunk, the call site address will be the same as the function
        # address...I think
        try:
            func = cfg.kb.functions[func]
        except BaseException:
            return False

        cs = list(func.get_call_sites())
        block = list(func.block_addrs_set)

        if len(cs) == 1 and len(block) == 1:
            if cs[0] == func.addr:
                return True
        else:
            if len(block) == 1:
                ins = self.get_block_exit(block[0])
                if ins:
                    if ins.mnemonic == "jmp" and ins.address == func.addr:
                        return True
        return False

    def convert_thunk_to_callees(self, cfg, thunk) -> list:
        """
        If a function is a thunk, we find the predecessors of the thunk.
        The preds are basic blocks that called the thunk function. If we get the last instruction
        address of the basic block, it will be the callee of the thunk (since angr breaks basic blocks
        at calls)

        Paramters:
                thunk: int address

        Reture:
                callees: list of address that called the thunk
        """
        callees = []
        # preds = self.cfg.model.get_any_node(thunk, anyaddr=True).predecessors
        preds = cfg.get_any_node(thunk, anyaddr=True).predecessors

        for pred in preds:
            # the callee is the last address of this block
            callee = self.get_block_exit(pred.addr)
            if callee:
                callee = callee.addr
            else:
                return []
            if not self.thunk(callee, cfg):
                callees.append(callee)
        return callees

    def get_call_sites(self) -> Dict[int, list]:
        """
        Get all call sites from functions available thru the CFG
        :return: Dict[func_addr, List[callsite block address]]
        """
        call_sites = {}
        for func_addr, func_obj in self.cfg.kb.functions.items():
            call_sites[func_addr] = list(func_obj.get_call_sites())
        return call_sites

    def call_sites_to_targets_initial(self) -> Dict[int, Any]:
        """
        First pass to resolve all call targets -- doesn't consider thunk functions that wrap imports
        Map the call_site block address to the callee function address
        :return: 'site_target_map' Dict[callsite_block_address, callee_address]
        """
        call_sites = self.get_call_sites()
        site_target_map = {}
        for func_addr, cs in call_sites.items():
            for indiv_cs in cs:
                indirect, addr, jumpkind = self.is_indirect(indiv_cs)
                if indirect:
                    resolved = self.resolve(addr, jumpkind)
                    if resolved:
                        if len(resolved) == 1:
                            resolved = resolved[0]
                        site_target_map[indiv_cs] = resolved
                    else:
                        site_target_map[indiv_cs] = "Unresolved"
                else:
                    caller = self.get_block_exit(indiv_cs)
                    if caller:
                        if caller.op_str.startswith("0x"):  # direct call
                            site_target_map[indiv_cs] = int(caller.op_str, 16)
                        elif caller.mnemonic == "call" or caller.mnemonic.startswith(
                            "j"
                        ):  # not a normal indirect/direct call. Unknown case.
                            log.error(
                                f"{caller.op_str} needs to be handled...handle it."
                            )
        return site_target_map

    def call_sites_to_targets(self) -> Dict[int, Any]:
        """
        Jumps into thunks and finds "real" call targets
        Create all functions' call targets (in the call site)
        :return: Dict[callsite_block_address, callee_address]
        """
        full_map = {}
        site_target_map = self.call_sites_to_targets_initial()
        for k, v in site_target_map.items():
            if self.thunk(self.cfg, v):
                ins = self.get_block_exit(v)
                if ins:
                    indirect, addr, jk = self.is_indirect(ins.address)
                    if indirect:
                        resolved = self.resolve(addr, jk)
                        if resolved:
                            if len(resolved) == 1:
                                resolved = resolved[0]
                            full_map[k] = resolved
                            continue
            full_map[k] = v
        return full_map

    def resolve_called_targets(self) -> Dict[int, str]:
        """
        Maps call targets to subroutines (from cfg.kb.functions) or imports
        Some unresolvable targets can be resolved by cheating...see def call_site_to_cfg_function_import

        :return call site (basic block) address mapped to string name
        :rtye: dict
        """
        insert_imps = {}
        site_target_map = self.call_sites_to_targets()
        call_site_to_cfg_function_import = self.cfg_imports_to_call_sites()
        for cs, target in site_target_map.items():
            if target in self.exports.keys():
                insert_imps[cs] = self.exports[target]
            elif target in self.imports.keys():
                insert_imps[cs] = self.imports[target]
            elif self.cfg.kb.functions.contains_addr(target):
                insert_imps[cs] = self.cfg.kb.functions[target].name
            elif target == "Unresolved":  # cheat
                if cs in call_site_to_cfg_function_import.keys():
                    insert_imps[cs] = call_site_to_cfg_function_import[cs]
            else:
                insert_imps[cs] = target
        return insert_imps

    def block_to_func(self, block_addr) -> Any:
        """
        Get the current function from the block's start address
        :param block_addr: block **start** address
        :return:
        """
        node: CFGNode = self.cfg.model.get_any_node(block_addr)
        if node:
            function_addr = node.function_address
            func = self.cfg.kb.functions[function_addr]
            return function_addr, func.name
        else:
            return None, None

    def call_graph_for_sink(
        self, sink_func: Union[int, str, Function], maxpaths=100
    ) -> Tuple[List, List]:
        """
        DFS to search all the potential callgraphs for the sink.
        Warning: It's impossible to find all the potential call_graphs for a sink
                     in the cfg, because DFS the caller functions will encounter path
                     explosion problem.
        :param sink_func: sink function (name, address or Function)
        :param maxpaths: Used as a constraint for the max call_paths to find.
        :return: (call_graph, loops) call_graphs and loops recorded
        """
        # init steps
        stack = []
        path_recoder = {}
        call_graph = []
        loops = []
        path_id = 0
        cur_depth = 0
        last_depth = -1

        def update_recoder(path_id: int, func_name: str, depth: int):
            """
            Function used for updating the recoder
            """
            if path_id in path_recoder.keys():
                path_recoder[path_id].append(func_name)
            else:
                if path_id == 0:
                    path_recoder[path_id] = [func_name]
                else:
                    ori_path_until_dep = path_recoder[path_id - 1][:depth]
                    ori_path_until_dep.append(func_name)
                    path_recoder[path_id] = ori_path_until_dep

        def loop_in_recorder(path_id: int, func_name: str) -> Union[List, Any]:
            """
            Check if there are any function loops in this path
            Example: function A, B, C, D  A <- B <- C <- D <- A
            """
            if path_id in path_recoder.keys():
                if func_name in path_recoder[path_id]:
                    idx = path_recoder[path_id].index(func_name)
                    return path_recoder[path_id][idx:]
            return None

        def get_sinkname(sink_func: Union[int, str, Function]) -> Union[int, Any]:
            """
            Get sink function address from any legal representation
            """
            if isinstance(sink_func, int):
                func: Function = self.cfg.kb.functions.function(addr=sink_func)
                if func:
                    return func.name
                return None
            elif isinstance(sink_func, Function):
                return sink_func.name
            elif isinstance(sink_func, str):
                return sink_func
            else:
                return None

        sink_name = get_sinkname(sink_func)
        if not sink_name:
            log.warning(f"Did not find target sink func {sink_func}.")
            return call_graph, loops
        stack.append((sink_name, cur_depth))
        if path_id > maxpaths:
            return call_graph, loops
        # DFS with the stack
        while len(stack):
            if len(call_graph) < (path_id + 1):
                call_graph.append([])
            # pop the current function item to operate
            sink_name, sink_depth = stack.pop()
            # DFS algo has been backtraced, which means found another path
            if sink_depth <= last_depth:
                path_id += 1
                call_graph.append([])
                # init the new path
                call_graph[path_id] = call_graph[path_id - 1][:sink_depth]
                cur_depth = sink_depth
            # update the last depth
            last_depth = sink_depth
            # update the call_graph path
            call_graph[path_id].append(sink_name)
            update_recoder(path_id, sink_name, sink_depth)
            # for the next depth (push stack)
            cur_depth += 1
            caller_set = set()
            for k, v in path_recoder.items():
                print(k, v)
            for callsite_blk_addr, tar_name in self.call_targets.items():
                if tar_name == sink_name:
                    caller = self.block_to_func(callsite_blk_addr)
                    if not caller:
                        log.warning(f"Did not find caller")
                        continue
                    caller_addr, caller_name = caller
                    if caller_name in caller_set:
                        continue
                    caller_set.add(caller_name)
                    loop = loop_in_recorder(path_id, caller_name)
                    if loop is not None:
                        loops.append(loop)
                    else:
                        stack.append((caller_name, cur_depth))
        return call_graph, loops

    def reachability_callers_for_sink(self, sink_name: str) -> List:
        """
        Get a function-level reachability map(all the potential callers)
        for the sink function.

        :param sink_name:
        :return:
        """
        reachability_caller_map = {}
        queue = deque()
        visited = set()
        queue.append((sink_name, 0))
        while len(queue):
            cursink_name, num_steps = queue.pop()
            if (
                cursink_name in visited
                or cursink_name in reachability_caller_map.keys()
            ):
                continue
            visited.add(cursink_name)
            reachability_caller_map[cursink_name] = num_steps
            for callsite_block_addr, callee_name in self.call_targets.items():
                if callee_name == cursink_name:
                    _, caller_name = self.block_to_func(callsite_block_addr)
                    if not caller_name:
                        continue
                    if caller_name not in visited:
                        queue.append((caller_name, num_steps + 1))

        # Combine with the block-level reachability map
        for callsite_block_addr, callee in self.call_targets.items():
            if callee == sink_name:
                blocklv_rm = self.get_reachability_map(self.cfg, callsite_block_addr)
                for blk_addr, num in blocklv_rm.items():
                    node = self.cfg.model.get_any_node(blk_addr)
                    func = self.cfg.kb.functions[node.function_address]
                    if func.name not in reachability_caller_map.keys():
                        reachability_caller_map[func.name] = num
        return sorted(reachability_caller_map.items(), key=lambda item:item[1])


    # def call_graph_for_sink(self, sink_func: Union[int, str, Function], depth: int=0, path_id = 0, call_graph=None):
    #     # init the call_graph
    #     if call_graph is None:
    #         call_graph = []
    #     # found a new path
    #     if len(call_graph) < (path_id + 1):
    #
    #     if depth and len(call_graph) == depth:
    #         call_graph.append(0)
    #         return call_graph
    #     # function address
    #     if isinstance(sink_func, int):
    #         func_addr = sink_func
    #         sink_func = self.cfg.kb.functions[func_addr]
    #         if not sink_func:
    #             log.debug(f"Didn't find function for function-address: 0x{func_addr:x}.")
    #             return call_graph
    #         func_name = sink_func.name
    #     elif isinstance(sink_func, str):
    #         func_name = sink_func
    #         sink_func = self.cfg.kb.functions.function(name=func_name)
    #         if not sink_func:
    #             log.debug(f"Didn't find function for name: {func_name}.")
    #             return call_graph
    #     # function
    #     elif isinstance(sink_func, Function):
    #         func_name = sink_func.name
    #     else:
    #         raise ValueError()
    #     for callsite_blk_addr, tar_name in self.call_targets.items():
    #         if tar_name == func_name:
    #             node: CFGNode = self.cfg.model.get_any_node(callsite_blk_addr)
    #             if node:
    #                 caller_addr = node.function_address
    #                 call_graph.append(caller_addr)
    #                 # TODO:test
    #                 caller_name = self.cfg.kb.functions[caller_addr].name
    #                 log.warning(f'added {func_name} <- {caller_name}')
    #                 self.call_graph_for_sink(caller_addr, depth, call_graph)
    #     call_graph.append(0)
    #     return call_graph
