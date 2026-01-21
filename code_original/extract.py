from idautils import *
from idaapi import *
from bclass import *
from capstone import *

import pickle
import hashlib
import sys
import csv

def get_list():
	function_list = []
	with open(r'F:\everything\d_link\d_link_funcs.csv', 'rb') as csvfile:
		r = csv.reader(csvfile, delimiter=',')
		for row in r:
			for item in row:
				if item:
					item = item.replace("*","")
					item = item.strip()
					function_list.append(item)
	return function_list

def dump_function_details(func_ea , name = None):
	md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	if name:
		func_name = name
	else:
		func_name = GetFunctionName(func_ea)
	
	bFunc = BFunc(func_ea)
	bFunc.name = func_name
	
	for bb in FlowChart(get_func(func_ea), flags=FC_PREDS):
		bBasicBlock = BBasicBlock(str(hex(bb.startEA)))
		
		preds = bb.preds()
		succs = bb.succs()
		
		if preds:
			preds_list = []
			for preds_block in preds:
				preds_list.append(str(hex(preds_block.startEA)))
				
			bBasicBlock.preds = preds_list
			
		if succs:
			succs_list = []
			for succs_block in succs:
				succs_list.append(str(hex(succs_block.startEA)))
				
			bBasicBlock.succs = succs_list

		
		for head in Heads(bb.startEA,bb.endEA):
			if isCode(getFlags(head)):
				bInstr = BInstr(head)
				
				#next = NextHead(head, bb.endEA+1)
				next = NextHead(head)
				length = 0
				if next < (bb.endEA + 1):
					length = next - head
				else: 
					length = bb.endEA - head
				
				bytes = GetManyBytes(head, length, False)
				disasm_striped = ""
				if bytes:
					for i in md.disasm(bytes, 0x00):
						disasm_striped = i.mnemonic + " " + i.op_str
						break
					bytes = bytes.encode('hex')
				
				disasm = GetDisasm(head)
				
				bInstr.address = str(hex(head))
				bInstr.disasm = disasm
				bInstr.bytes = bytes
				bInstr.disasm_striped = disasm_striped
				
				
				mnem = GetMnem(head)
				if mnem:
					bInstr.mnem = mnem
				
				bBasicBlock.add_instr(bInstr)
				
		bBasicBlock.precess_bb()
		bFunc.add_bb(bBasicBlock)
	bFunc.print_func_v1()
	save_function(bFunc)
	return bFunc

def dump_one_function(func_name):
	for seg in Segments():
		if SegName(seg) == ".text":
			functions = Functions(seg)
			
			for func_ea in functions:
				name = GetFunctionName(func_ea)
				if name == func_name:
					dump_function_details(func_ea)

def dump_functions(dbg): # dbg = {name:addr}
	func_list = get_list()
	if dbg:
		for func in func_list:
			dump_function_details(dbg[func],func)
			return
	for seg in Segments():
		if SegName(seg) == ".text":
			functions = Functions(seg)
			
			for func_ea in functions:
				name = GetFunctionName(func_ea)
				if name in func_list:
					dump_function_details(func_ea)

def save_function(bFunc):
	p_name = GetInputFile()
	f_name = bFunc.name
	# m = re.match('^sub_',f_name)
	# if m:
	# 	add = m.group(1)
	# 	f_name = dbg[add]


	file_name = r"F:\everything\d_link\d_link_results"+'\\' + p_name + "_" + f_name + ".pkl"
	with open(file_name, 'wb') as f:
		pickle.dump(bFunc, f)

if __name__ == '__main__':
	idaapi.autoWait()
	#func_name = "show_ciphers"
	#dump_one_function(func_name)
	p_name = GetInputFile()
	dbg_file = r"F:\everything\to_yifei\dbg"+'\\' + p_name + ".txt"
	dbg = {}
	if os.path.exists(dbg_file):
		with open(dbg_file,'r') as d:
			funcs = d.readlines()
			for f in funcs:
				name,addr = f.strip().split(":")
				dbg[name] = int(addr, 16)

	dump_functions(dbg)
	Exit(1)

