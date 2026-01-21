import hashlib
import pickle
import re

class BFunc:
	def __init__(self, start_address):
		self.program = None
		self.name = None
		self.start_address = start_address
		self.bbs = []
		self.hash = None
		self.flag = None
	
	def add_bb(self, bb):
		self.bbs.append(bb)
	
	def print_func_v1(self):
		for item in self.bbs:
			item.print_bb()

	def print_func_v2(self):
		print "function name: " + self.name
		


class BBasicBlock:
	CMP_REPS = ["short loc_", "loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  	"qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
 	"stru_", "dbl_", "locret_"]
	CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr "]
	CMP_REGS_X64 = ["rax", "eax", "ax", "al", "rbx", "ebx", "bx", "bl", "rcx", "ecx", "cx", "cl", 
	"rdx", "edx", "dx", "dl", "rsi", "esi", "si", "sil", "rdi", "edi", "di", "dil", "rbp", "ebp", 
	"bp", "bpl", "rsp", "esp", "sp", "spl", "r8", "r8d", "r8w", "r8b", "r9", "r9d", "r9w", "r9b", 
	"r10", "r10d", "r10w", "r10b", "r11", "r11d", "r11w", "r11b", "r12", "r12d", "r12w", "r12b", 
	"r13", "r13d", "r13w", "r13b", "r14", "r14d", "r14w", "r14b", "r15", "r15d", "r15w", "r15b"]
	CMP_REGS_ARM64 = ["X0","X1","X2","X3","X4","X5","X6","X7","X8","X9","X10","X11","X12","X13","X14","X15",
	"X16","X17","X18","X19","X20","X21","X22","X23","X24","X25","X26","X27","X28","X29","X30",
	"W0","W1","W2","W3","W4","W5","W6","W7","W8","W9","W10","W11","W12","W13","W14","W15",
	"W16","W17","W18","W19","W20","W21","W22","W23","W24","W25","W26","W27","W28","W29","W30"]
	CMP_REGS_ARM32 = ["R0","R1","R2","R3","R4","R5","R6","R7","R8","R9","R10","R11","R12","R13","R14","R15","SP"]

	def __init__(self, start_address):
		self.function = None
		self.start_address = start_address
		self.end_address = None
		self.binstrs = []
		self.preds = []
		self.succs = []
		self.hash_v1 = None
		self.hash_v2 = None
		self.hash_v3 = None
		
		self.neighbour_disasm_list = None
		self.mnen_list = None
		self.disasm_list = None
		self.flag = None
		self.flag_v2 = None
		
	def add_instr(self, binstr):
		self.binstrs.append(binstr)
	def add_preds(self, pred):
		self.preds.append(pred)
	def add_succs(self, succ):
		self.succs.append(succ)
		
	def normalize_instruction(self, instr_str):
		instr_str = instr_str.split(";")[0]
		for rep in self.CMP_REPS:
			if rep in instr_str:
				instr_str = re.sub(rep + "[a-f0-9A-F]+", "func", instr_str)

		for sub in self.CMP_REMS:
			if sub in instr_str:
				instr_str = instr_str.replace(sub, "")
		
		for r in self.CMP_REGS_ARM64:
			if r in instr_str:
				instr_str = re.sub(r,  'reg', instr_str)

		#replace memory 
		instr_str = re.sub('\[.*\]',  'mem', instr_str)
		
		#replace address 
		instr_str = re.sub('0x[0-9a-f]{5}',  'address', instr_str)
		
		#clean up white space
		instr_str = re.sub("[ \t\n]+$", "", instr_str)
		
		return instr_str
	
	def set_mnen_list(self):
		mnen_list = []
		for binstr in self.binstrs:
			mnen_list.append(binstr.mnem)
		self.mnen_list = mnen_list
		
	def set_hash_v1(self):
		m = hashlib.md5()
		mnem_str = ' '.join(self.mnen_list) 
		m.update(mnem_str)
		md5 = str(m.hexdigest())
		self.hash_v1 = md5
		
	def set_disasm_list(self):
		disasm_list = []
		for instr in self.binstrs:
			d = re.sub('\t+',' ' ,instr.disasm)
			d = re.sub(' +',' ' ,d)
			n_disasm = self.normalize_instruction(d)
			disasm_list.append(n_disasm)
		self.disasm_list = disasm_list

	def set_hash_v2(self):
		m = hashlib.md5()
		instr_str = ' '.join(self.disasm_list) 
		m.update(instr_str)
		md5 = str(m.hexdigest())
		self.hash_v2 = md5
		
	def precess_bb(self):
		self.set_mnen_list()
		self.set_hash_v1()
		self.set_disasm_list()
		self.set_hash_v2()
		

	def print_bb(self):
		print "BB name : " + str(self.start_address)
		
		print "BB preds : "
		print self.preds
		
		print "BB succs :"
		print self.succs

		print "BB disam_list :"
		print ' '.join(self.disasm_list)
		
		print "BB hash : " + self.hash_v2
		
		for item in self.binstrs:
			item.print_instr()

		
class BInstr:
	def __init__(self, start_address):
		self.basicblock = None
		self.start_address = start_address
		self.disasm = None
		self.mnem = None
		self.bytes = None
		self.disasm_striped = None
		self.flag = None
		self.hash = None

	def print_instr(self):
		instr = '{:>10} | {:>18} | {:>0} | {:>0}'.format(self.address, self.bytes, self.disasm_striped, self.disasm)
		print instr