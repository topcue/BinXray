from my_config import setup_ida_sys_path, wsl_to_win_path

setup_ida_sys_path()

from my_config import (
    PICKLE_PATH,
    FUNCS_CSV_PATH
)


# IDA 7.7 + Python 3.8 port of the original IDA 6.8 script

import os
import csv
import pickle

import idautils
import idaapi
import ida_bytes
import ida_funcs
import ida_segment
import ida_nalt
import ida_gdl
import idc

from bclass import *  # assumes BFunc/BBasicBlock/BInstr exist and are Py3-compatible
from capstone import *

CSV_PATH = FUNCS_CSV_PATH
CSV_PATH = wsl_to_win_path(CSV_PATH)
PICKLE_PATH = wsl_to_win_path(PICKLE_PATH)


def get_list():
    function_list = []
    # Python 3: use text mode + newline=''
    with open(CSV_PATH, "r", newline="", encoding="utf-8", errors="ignore") as csvfile:
        r = csv.reader(csvfile, delimiter=",")
        for row in r:
            for item in row:
                if item:
                    item = item.replace("*", "")
                    item = item.strip()
                    if item:
                        function_list.append(item)
    return function_list


def _get_input_basename():
    # Similar role as GetInputFile() in old code (file name without path)
    # ida_nalt.get_root_filename() typically returns base name.
    return ida_nalt.get_root_filename()


def dump_function_details(func_ea, name=None):
    print(f"  [DEBUG] dump_function_details({func_ea})")
    # NOTE: original code hard-coded ARM mode.
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    func_name = name if name else idc.get_func_name(func_ea)
    if not func_name:
        func_name = f"sub_{func_ea:X}"

    print(f"  [DEBUG] func_name: {func_name}")

    bFunc = BFunc(func_ea)
    bFunc.name = func_name

    f = ida_funcs.get_func(func_ea)
    if not f:
        # Not a function in IDA database
        return None

    print(f"  [DEBUG] {func_name} in ida_funcs")

    # flags=idaapi.FC_PREDS keeps predecessor info similar to original
    for bb in ida_gdl.FlowChart(f, flags=idaapi.FC_PREDS):
        bBasicBlock = BBasicBlock(hex(bb.start_ea))

        preds = list(bb.preds())
        succs = list(bb.succs())

        if preds:
            bBasicBlock.preds = [hex(p.start_ea) for p in preds]
        if succs:
            bBasicBlock.succs = [hex(s.start_ea) for s in succs]

        # iterate heads in [start_ea, end_ea)
        for head in idautils.Heads(bb.start_ea, bb.end_ea):
            if ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                bInstr = BInstr(head)

                # old: next = NextHead(head)
                # new: idc.next_head(ea[, maxea])
                nxt = idc.next_head(head, bb.end_ea)
                if nxt == idc.BADADDR:
                    length = 0
                else:
                    # original logic compared with (bb.endEA + 1)
                    if nxt < bb.end_ea:
                        length = nxt - head
                    else:
                        length = bb.end_ea - head

                raw = b""
                if length > 0:
                    raw = ida_bytes.get_bytes(head, length) or b""

                disasm_striped = ""
                if raw:
                    # capstone wants actual address; original used 0x00
                    for insn in md.disasm(raw, head):
                        disasm_striped = f"{insn.mnemonic} {insn.op_str}".strip()
                        break

                # Python 3: bytes -> hex string
                raw_hex = raw.hex() if raw else ""

                # old: GetDisasm(head)
                # new: idc.generate_disasm_line(head, flags)
                disasm = idc.generate_disasm_line(head, 0) or ""

                bInstr.address = hex(head)
                bInstr.disasm = disasm
                bInstr.bytes = raw_hex
                bInstr.disasm_striped = disasm_striped

                # old: GetMnem(head)
                mnem = idc.print_insn_mnem(head)
                if mnem:
                    bInstr.mnem = mnem

                bBasicBlock.add_instr(bInstr)

        bBasicBlock.precess_bb()
        bFunc.add_bb(bBasicBlock)

    bFunc.print_func_v1()
    save_function(bFunc)
    return bFunc


# def dump_one_function(func_name):
#     for seg_ea in idautils.Segments():
#         if ida_segment.get_segm_name(ida_segment.getseg(seg_ea)) == ".text":
#             for func_ea in idautils.Functions(seg_ea):
#                 name = idc.get_func_name(func_ea)
#                 if name == func_name:
#                     dump_function_details(func_ea)
#                     return


def dump_functions(dbg):  # dbg = {name: addr}
    func_list = get_list()

    print()
    print(f"[DEBUG] func_list from {CSV_PATH}")
    for func in func_list:
        print(f"[DEBUG] func: {func}")
    print()

    if dbg:
        # Preserve original behavior: process the first match and return
        for func in func_list:
            if func in dbg:
                dump_function_details(dbg[func], func)
                return
        return

    for seg_ea in idautils.Segments():
        if ida_segment.get_segm_name(ida_segment.getseg(seg_ea)) == ".text":
            print(f"[DEBUG] Segment name: .text")
            for func_ea in idautils.Functions(seg_ea):
                name = idc.get_func_name(func_ea)
                if name in func_list:
                    print(f"[DEBUG] func_name from ida: {name}")
                    dump_function_details(func_ea)


def save_function(bFunc):
    p_name = _get_input_basename()
    f_name = bFunc.name

    os.makedirs(PICKLE_PATH, exist_ok=True)
    file_name = os.path.join(PICKLE_PATH, f"{p_name}_{f_name}.pkl")

    with open(file_name, "wb") as f:
        pickle.dump(bFunc, f, protocol=pickle.HIGHEST_PROTOCOL)


# def _load_dbg_map():
#     p_name = _get_input_basename()
#     dbg_file = os.path.join(DBG_DIR, f"{p_name}.txt")
#     dbg = {}
#     if os.path.exists(dbg_file):
#         with open(dbg_file, "r", encoding="utf-8", errors="ignore") as d:
#             for line in d:
#                 line = line.strip()
#                 if not line or ":" not in line:
#                     continue
#                 name, addr = line.split(":", 1)
#                 name = name.strip()
#                 addr = addr.strip()
#                 if not name or not addr:
#                     continue
#                 try:
#                     dbg[name] = int(addr, 16)
#                 except ValueError:
#                     pass
#     return dbg


def main():
    print("[DEBUG] invoke idaapi.auto_wait()")
    idaapi.auto_wait()
    print("[DEBUG] complete idaapi.auto_wait()")

    # dbg = _load_dbg_map()
    dbg = None
    dump_functions(dbg)

    idc.qexit(0)


if __name__ == "__main__":
    main()

# EOF
