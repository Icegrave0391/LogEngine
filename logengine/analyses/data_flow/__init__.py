from .definition_util import DefinitionUtil
from .function_handler import NaiveHandler
from .wget_handler import WgetHandler
from .execution_rda import ExecutionFlowRDA
from angr.analyses import register_analysis

register_analysis(ExecutionFlowRDA, "EFReachingDefinitions")
