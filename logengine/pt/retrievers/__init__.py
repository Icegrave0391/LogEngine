import re
import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
# filters
ld = r'(.*/ld.*\.so)'

raw_patterns = [ld]
compiled_patterns = [re.compile(p) for p in raw_patterns]

# raw data retreiver
def retrieve_process_thread(tpid: str):
    tid, pid = re.split(r'/', tpid)
    if not tid or not pid:
        log.info(f'failed to retrieve tid and pid from field {tpid}')
    return int(tid), int(pid)

def retrieve_symbol(symwoff: str):
    if symwoff.find('unknown') >= 0:
        return 'unknown', 0
    sym, offset = re.split(r'\+', symwoff)
    if not sym or not offset:
        log.info(f'failed to retrieve symbol and offset from field {symwoff}')
    return sym, int(offset, 16)

def retrieve_execfile(exec: str):
    execf = re.findall(r'\((.*?)\)', exec)
    if len(execf) != 1:
        log.info(f'failed to retrieve execfile from field {exec}')
    return execf[0]

raw_retreiver = {
    'fields_noflag_len': 9,
    'fields_flag_len': 10,
    't&pid': retrieve_process_thread,
    'symwoff': retrieve_symbol,
    'exec': retrieve_execfile
}
