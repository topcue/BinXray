import pickle
from bclass import *
import networkx as nx
import editdistance
import csv
from math import *
import re
import os
import matplotlib.pyplot as plt
import json
import time

CMP_REGS_X64 = ["rax", "eax", "ax", "al", "rbx", "ebx", "bx", "bl", "rcx", "ecx", "cx", "cl", 
	"rdx", "edx", "dx", "dl", "rsi", "esi", "si", "sil", "rdi", "edi", "di", "dil", "rbp", "ebp", 
	"bp", "bpl", "rsp", "esp", "sp", "spl", "r8", "r8d", "r8w", "r8b", "r9", "r9d", "r9w", "r9b", 
	"r10", "r10d", "r10w", "r10b", "r11", "r11d", "r11w", "r11b", "r12", "r12d", "r12w", "r12b", 
	"r13", "r13d", "r13w", "r13b", "r14", "r14d", "r14w", "r14b", "r15", "r15d", "r15w", "r15b"]
CMP_REGS_ARM = ["R0","R1","R2","R3","R4","R5","R6","R7","R8","R9","R10","R11","R12","R13","R14","R15","SP"]
def get_bb_by_address(address, func):
	for bb in func.bbs:
		if bb.start_address == address:
			return bb
	return None

def read_func_info(function_name, version):
	input_path = r'F:\everything\binary_exp\freetype\pkl'+'\\' + version + '.bin@_@' + function_name + '.pkl'
	func = None
	try:
		with open(input_path, 'rb') as input:
			func = pickle.load(input)
	except IOError as e:
		print "error:",function_name
		return None
	return func

def preprocess_func(func):
	for bb in func.bbs:
		pred_disam_list = []
		for pred in bb.preds:
			tmp_bb = get_bb_by_address(pred, func)
			if tmp_bb:
				pred_disam_list.append(tmp_bb.disasm_list)

		succ_disam_list = []
		for succ in bb.succs:
			tmp_bb = get_bb_by_address(succ, func)
			if tmp_bb:
				succ_disam_list.append(tmp_bb.disasm_list)

		bb.neighbour_disasm_list = [pred_disam_list, succ_disam_list]
	return func

def update_map(map, key, value, index):
	if index == 0:
		if not key in map:
			map[key] = [[],[]]
	elif index == 1:
		map[key][0].append(value)
	elif index == 2:
		map[key][1].append(value)
	return map

def match_two_funcs(func1, func2):
	map = {}
	for bb1 in func1.bbs:
		update_map(map, bb1.hash_v2, None, 0)
		update_map(map, bb1.hash_v2, bb1, 1)
	for bb2 in func2.bbs:
		update_map(map, bb2.hash_v2, None, 0)
		update_map(map, bb2.hash_v2, bb2, 2)
	return map

def match_two_funcs_v2(func1, func2):
	map = {}
	index = 0
	mene1 = []
	mene2 = []
	for bb1 in func1.bbs:
		mnen1.append(bb1.mnen_list)
		
	for bb2 in func2.bbs:
		mnen2.append(bb2.mnen_list)
	


def cal_score_trace(trace0, trace1):
	len0 = len(trace0)
	len1 = len(trace1)
	len_max = max(len0, len1)

	dist = editdistance.eval(trace0 , trace1)
	try:
		score = float(len_max - dist) / float(len_max)
	except ZeroDivisionError:
		return 0
	else:
		return score

def cal_score_traceset(traceset0, traceset1):
	
	len0 = len(traceset0)
	len1 = len(traceset1)
	score_p1 = 1.0 / (abs(len0 - len1) + 1)
	
	score_p2 = 0
	if len0 < len1:
		total_score = 0
		for trace1 in traceset1:
			score_max = 0
			for trace0 in traceset0:
				score = cal_score_trace(trace0, trace1)
				if score > score_max:
					score_max = score
			total_score += score_max
		score_p2 = float(total_score) / len1
	else:
		total_score = 0
		for trace0 in traceset0:
			score_max = 0
			for trace1 in traceset1:
				score = cal_score_trace(trace0, trace1)
				if score > score_max:
					score_max = score
			total_score += score_max
		score_p2 = float(total_score) / len0
	
	score_final = score_p1 * score_p2
	
	return score_final

def cal_score_bb(bb0, bb1):
	pred_score = 0
	succ_score = 0

	if len(bb0.neighbour_disasm_list[0]) == 0 and len(bb1.neighbour_disasm_list[0]) == 0:
		pred_score = 1
	elif len(bb0.neighbour_disasm_list[0]) == 0 or len(bb1.neighbour_disasm_list[0]) == 0:
		pred_score = 0
	else:
		pred_score = cal_score_traceset(bb0.neighbour_disasm_list[0], bb1.neighbour_disasm_list[0])

	if len(bb0.neighbour_disasm_list[1]) == 0 and len(bb1.neighbour_disasm_list[1]) == 0:
		succ_score = 1
	elif len(bb0.neighbour_disasm_list[1]) == 0 or len(bb1.neighbour_disasm_list[1]) == 0:
		succ_score = 0
	else:
		succ_score = cal_score_traceset(bb0.neighbour_disasm_list[1], bb1.neighbour_disasm_list[1])

	

	score_final = (pred_score + succ_score) / 2
	
	return score_final

def handle_unmatched(record):
	final_return = [[],[]]
	score_map = []
	for item0 in record[0]:
		tmp_record = []
		for item1 in record[1]:
			tmp_score = cal_score_bb(item0, item1)
			tmp_record.append(tmp_score)
		score_map.append(tmp_record)
	

	len0 = len(record[0])
	len1 = len(record[1])

	len_min = min(len0, len1)
	

	list0 = []
	list1 = []

	for x in range(len_min):
		max_score = 0
		index_row = 0
		index_col = 0
		for i in range(len(record[0])):
			for j in range(len(record[1])):
				if score_map[i][j] > max_score:
					max_score = score_map[i][j]
					index_row = i
					index_col = j

		for i in range(len(record[0])):
			score_map[i][index_col] = -1
		for j in range(len(record[1])):
			score_map[index_row][j] = -1

		list0.append(index_row)
		list1.append(index_col)

	if len0 < len1:
		rest_set = set(range(0, len1)) - set(list1)
		
		for item in rest_set:
			final_return[1].append(record[1][item].start_address)
	else:
		rest_set = set(range(0, len0)) - set(list0)
		
		for item in rest_set:
			final_return[0].append(record[0][item].start_address)
	
	return final_return
def get_diff_bbs(map):
	func1_bb_list = []
	func2_bb_list = []
	for k in map.keys():
		record = map[k]
		#remove equal match
		if len(record[0]) == len(record[1]):
			pass

		#tag unmatched
		elif len(record[0]) == 0:
			for item in record[1]:
				func2_bb_list.append(item.start_address)

		#tag unmatched
		elif len(record[1]) == 0:
			for item in record[0]:
				func1_bb_list.append(item.start_address)

		#handle the rest
		else:
			
			result = handle_unmatched(record)
			if result[0]:
				func1_bb_list.extend(result[0])
			if result[1]:
				func2_bb_list.extend(result[1])
	func1_bb_list = list(set(func1_bb_list))
	func2_bb_list = list(set(func2_bb_list))
	return [func1_bb_list, func2_bb_list]

def get_diff_bbs_v2(map):
	func1_bb_list = []
	func2_bb_list = []
	tmp1 = []
	tmp2 = []
	for k in map.keys():
		record = map[k]
		#remove equal match
		if len(record[0]) == len(record[1]):
			pass

		#tag unmatched
		elif len(record[0]) == 0:
			for item in record[1]:
				tmp2.append(item)

		#tag unmatched
		elif len(record[1]) == 0:
			for item in record[0]:
				tmp1.append(item)

		#handle the rest
		else:
			
			result = handle_unmatched(record)
			if result[0]:
				func1_bb_list.extend(result[0])
			if result[1]:
				func2_bb_list.extend(result[1])
	done1 = []
	done2 = []
	
	for i in range(len(tmp1)-1,-1,-1):
		trace1 = ' '.join(tmp1[i].disasm_list)
		for j in range(len(tmp2)-1,-1,-1):
			trace2 = ' '.join(tmp2[j].disasm_list)
			dist = editdistance.eval(trace1 , trace2)
			score = float(dist) / float(len(trace1))
			if score < 0.3:
				
				tmp1.pop(i)
				tmp2.pop(j)
				break
		
		
	for item in tmp1:
		func1_bb_list.append(item.start_address)

	for item in tmp2:
		func2_bb_list.append(item.start_address)
	
	
	func1_bb_list = list(set(func1_bb_list))
	func2_bb_list = list(set(func2_bb_list))
	return [func1_bb_list, func2_bb_list]


def extract_sig(function_name, vul_version, patch_version):

	vul_func = read_func_info(function_name, vul_version)
	if not vul_func:
		return None
	vul_func = preprocess_func(vul_func)

	patch_func = read_func_info(function_name, patch_version)
	if not patch_func:
		return None
	patch_func = preprocess_func(patch_func)

	map = match_two_funcs(vul_func, patch_func)
	
	diff = get_diff_bbs(map)

	return [vul_func, patch_func, diff]

def load_target_func(function_name, target_version):
	target_func = read_func_info(function_name, target_version)
	if not target_func:
		return None
	target_func = preprocess_func(target_func)
	return target_func

def isEmpty(diff):
	return len(diff[0]) == 0 and len(diff[1]) == 0

def build_trace_graph(bb_list, func):
	G = nx.DiGraph()
	for bb1 in bb_list:
		G.add_node(bb1.start_address)
		for bb2 in bb_list:
			if bb2.start_address in bb1.preds:
				G.add_edge(bb2.start_address, bb1.start_address)
			if bb2.start_address in bb1.succs:
				G.add_edge(bb1.start_address, bb2.start_address)

	roots = (v for v, d in G.in_degree() if d == 0)
	leaves = (v for v, d in G.out_degree() if d == 0)

	root_list = []
	for root in roots:
		root_list.append(root)

	leaf_list = []
	for leaf in leaves:
		leaf_list.append(leaf)

	all_paths = []
	for root in root_list:
		
		for leaf in leaf_list:
			if root == leaf:
				all_paths.extend([[root]])
			paths = nx.all_simple_paths(G, root, leaf)
			if paths:
				
				all_paths.extend(paths)

	return all_paths

def get_root_bbs_add(func):
	add_list = []
	for bb in func.bbs:
		if not bb.preds or not bb.succs:
			add_list.append(bb.start_address)
	
	return add_list

def add_list_to_bb_list(address_list, func):
	bb_list = []
	for add in address_list:
		bb = get_bb_by_address(add, func)
		if bb:
			bb_list.append(bb)
	return bb_list

def build_trace_graph_v2(bb_add_list_changed, bb_add_list_root, func):
	
	bb_add_list_root_in_func = get_root_bbs_add(func)
	

	bb_add_list_in_graph = list(set(bb_add_list_changed).union(set(bb_add_list_root)))
	bb_list_in_graph = add_list_to_bb_list(bb_add_list_in_graph, func)
	print "get bb list:"
	G = nx.DiGraph()
	for bb1 in bb_list_in_graph:
		G.add_node(bb1.start_address)
		for bb2 in bb_list_in_graph:
			if bb2.start_address in bb1.preds:
				G.add_edge(bb2.start_address, bb1.start_address)
			if bb2.start_address in bb1.succs:
				G.add_edge(bb1.start_address, bb2.start_address)
	print "finish graph:",len(G.nodes())
	if len(G.nodes()) > 40:
		print "too much diff"
		return -1

	roots = (v for v, d in G.in_degree() if d == 0)
	leaves = (v for v, d in G.out_degree() if d == 0)

	root_list = []
	for root in roots:
		root_list.append(root)

	leaf_list = []
	for leaf in leaves:
		leaf_list.append(leaf)


	all_paths = []
	for root in root_list:
		for leaf in leaf_list:
			
			if root == leaf and root in bb_add_list_root:
				all_paths.extend([[root]])

			paths = nx.all_simple_paths(G, root, leaf)

			if paths:
				ppath = []
				for path in paths:
					
					for b in path:
						
						if b in bb_add_list_root:
							ppath.append(path)
							break
				all_paths.extend(ppath)

	return all_paths


def build_trace_by_address(address_list, func):
	bb_list = []
	for add in address_list:
		bb = get_bb_by_address(add, func)
		if bb:
			bb_list.append(bb)
	trace_list = build_trace_graph(bb_list, func)
	return trace_list


def get_instr_seq(func, bb_list):
	instr_seq_list = []
	for item in bb_list:
		for bb in func.bbs:
			if item == bb.start_address:
				instr_seq_list.extend(bb.disasm_list)
	return instr_seq_list

def get_instr_list(func, trace_in_list):
	instr_list = []
	for trace in trace_in_list:
		tmp = get_instr_seq(func, trace)
		instr_list.append(tmp)
	return instr_list

def matching(source_trace_list, match_trace_list):
	len_s = len(source_trace_list)
	len_m = len(match_trace_list)

	len_trace_s = 0
	for item1 in source_trace_list:
		len_trace_s += len(item1)

	len_trace_m = 0
	for item1 in match_trace_list:
		len_trace_m += len(item1)

	base = len_s * len_trace_m + len_m * len_trace_s

	total_len = 0
	total_score = 0
	total_count = 0
	for item1 in source_trace_list:
		len1 = len(item1)
		total_len += len1
		for item2 in match_trace_list:
			len2 = len(item2)
			lenn = max(len1,len2)

			dist = editdistance.eval(item1 , item2)
			value = float(lenn - dist) / float(lenn)
			total_score += value * (len1 + len2) / base
			

	matching_score = total_score
	
	return matching_score

def matching_v2(source_trace_list, match_trace_list):
	trace_count = 0
	total_score = 0
	for item1 in source_trace_list:
		max_score = 0
		trace_count += 1
		len1 = len(item1)
		for item2 in match_trace_list:
			len2 = len(item2)
			lenn = max(len1,len2)

			dist = editdistance.eval(item1 , item2)
			value = float(lenn - dist) / float(lenn)
			if value > max_score:
				max_score = value
		total_score += max_score

	if trace_count > 0:
		return float(total_score) / float(trace_count)
	else:
		return -1

def matching_v3(source_trace_list, match_trace_list):
	total_score = 0
	total_len = 0
	for item1 in source_trace_list:
		max_score = 0
		item1 = " ".join(item1)
		for r in CMP_REGS_ARM:
			if r in item1:
				item1 = item1.replace(r, "reg")
		len1 = len(item1)
		for item2 in match_trace_list:
			item2 = " ".join(item2)
			for r in CMP_REGS_ARM:
				if r in item2:
					item2 = item2.replace(r, "reg")
			len2 = len(item2)
			dist = editdistance.eval(item1 , item2)
			value = float(1) / float(dist + 1)
			if value > max_score:
				max_score = value * len1
		total_score += max_score
		total_len += len1
	if total_len > 0:
		return float(total_score) / float(total_len)
	else:
		return -1
	
def matching_v4(source_trace_list, match_trace_list):
	trace_count = 0
	total_score = 0
	for item1 in source_trace_list:
		max_score = 0
		trace_count += 1
		item1 = " ".join(item1)
		for r in CMP_REGS_ARM:
			if r in item1:
				item1 = item1.replace(r, "reg")
		len1 = len(item1)
		for item2 in match_trace_list:
			item2 = " ".join(item2)
			for r in CMP_REGS_ARM:
				if r in item2:
					item2 = item2.replace(r, "reg")
			len2 = len(item2)
			lenn = max(len1,len2)

			dist = editdistance.eval(item1 , item2)
			value = float(lenn - dist) / float(lenn)
			if value > max_score:
				max_score = value
		total_score += max_score

	if trace_count > 0:
		return float(total_score) / float(trace_count)
	else:
		return -1	

def find_surruding(bb_address_list, func):
	result_list = []
	for bb in func.bbs:
		if bb.start_address in bb_address_list:
			result_list.extend(bb.preds)
			result_list.extend(bb.succs)
	return_re = set(result_list) - set(bb_address_list)
	return_re = list(return_re)
	#print return_re
	return return_re



def find_matched_bb(bb, map_x_to_t):
	record = map_x_to_t[bb.hash_v2]
	max_score = 0
	matched_index = -1
	for index in range(len(record[1])):
		tmp_score = cal_score_bb(bb, record[1][index])
		if tmp_score > max_score:
			max_score = tmp_score
			matched_index = index
	if matched_index >= 0:
		
		return record[1][index].start_address
	else:
		return None



def find_matched_bbs(bb_list, map_x_to_t, index):
	
	matched_bb_list = []
	if index == 1:
		for bb in bb_list:
			matched_bb = find_matched_bb(bb, map_x_to_t)
			if matched_bb:
				matched_bb_list.append(matched_bb)
	else:
		print  "ERROR!"
		return None
	return matched_bb_list

def get_slice(target_func):
	length = 3
	all_paths = []
	for bb in target_func.bbs:
		G = nx.DiGraph()
		G.add_node(bb.start_address)
		root = bb.start_address
		nodes1 = []
		nodes2 = []
		done = []
		if bb.succs:
			
			nodes1.extend(bb.succs)
			for bb1 in bb.succs:
				G.add_node(bb1)
				G.add_edge(bb.start_address, bb1)
			done.append(bb)
			while(length-1):	
				for b in add_list_to_bb_list(nodes1, target_func):
					
					if b in done:
						continue
					if b.succs:
						nodes2.extend(b.succs)
						done.append(b)
						
						for bb2 in b.succs:
							G.add_node(bb2)
							G.add_edge(b.start_address, bb2)
				nodes1 = nodes2
				nodes2 = []
				length -= 1
		
		leaves = (v for v, d in G.out_degree() if d == 0)
		
		for leaf in leaves:
			
			paths = nx.all_simple_paths(G, root, leaf)
			for path in paths:
				
				all_paths.append(path)
	return all_paths

		
def match_decision_v2(target_func, sig,all_paths):
	vul_func = sig[0]
	patch_func = sig[1]
	diff = sig[2]

	if isEmpty(diff):
		return "N VP no diff"

	v_to_t = match_two_funcs(vul_func, target_func)
	diff_v_to_t = get_diff_bbs_v2(v_to_t)

	p_to_t = match_two_funcs(patch_func, target_func)
	diff_p_to_t = get_diff_bbs_v2(p_to_t)

	same_v = isEmpty(diff_v_to_t)
	same_p = isEmpty(diff_p_to_t)

	if same_v and same_p:
		return "N VT/PT no diff"
	elif same_p:
		return "P"
	elif same_v:
		return "V"

	print "handle"

	print "start find surruding"
	s_v = find_surruding(diff[0], vul_func)
	s_p = find_surruding(diff[1], patch_func)
	print "end find surruding"

	DIFF0 = False
	DIFF1 = False
	
	vul_vp = []
	patch_vp = []

	print "diff0:",diff[0]
	print "diff1:",diff[1]
	if diff[0]:
		vul_vp = build_trace_graph_v2(diff[0] , s_v, vul_func) #T1
		print "get T1:"
	else:
		
		DIFF0 = True
	if diff[1]:
		patch_vp = build_trace_graph_v2(diff[1] , s_p, patch_func) #T2
		print "get T2"
	else:
		
		DIFF1 = True

	

	
	trace_list_vul_vp = get_instr_list(vul_func, vul_vp)
	
	trace_list_patch_vp = get_instr_list(patch_func, patch_vp)

	
	trace_list_tar = get_instr_list(target_func, all_paths)

	s_vt = matching_v3(trace_list_vul_vp, trace_list_tar) 
	s_pt = matching_v3(trace_list_patch_vp, trace_list_tar) 

	threshold = 0.5
	if not DIFF0 and not DIFF1:
		if s_vt > s_pt:
			return "V " + str(s_vt) + "/" + str(s_pt)
		if s_vt < s_pt:
			return "P " + str(s_vt) + "/" + str(s_pt)
		else:
			return "C can't tell"
	if not DIFF0 and  DIFF1:
		if 0.5 < s_pt:
			return "P " + str(s_pt)
		else:
			return "V " + str(s_pt)
	if  DIFF0 and not DIFF1:
		if 0.5 < s_vt:
			return "V " + str(s_vt)
		else:
			return "P " + str(s_vt)
	return "C can't tell"
	

	

def match_decision(target_func, sig):
	vul_func = sig[0]
	patch_func = sig[1]
	diff = sig[2]

	if isEmpty(diff):
		return "N VP no diff",[]

	v_to_t = match_two_funcs(vul_func, target_func)
	diff_v_to_t = get_diff_bbs(v_to_t)

	p_to_t = match_two_funcs(patch_func, target_func)
	diff_p_to_t = get_diff_bbs(p_to_t)

	same_v = isEmpty(diff_v_to_t)
	same_p = isEmpty(diff_p_to_t)

	
	if same_v and same_p:
		return "N VT/PT no diff",[]
	elif same_p:
		return "P",[]
	elif same_v:
		return "V",[]

	
	print "handle"
	
	
	s_v = find_surruding(diff[0], vul_func)
	s_p = find_surruding(diff[1], patch_func)
	

	
	matched_bb_list_v_t = []
	if s_v:
		s_v_bb = add_list_to_bb_list(s_v, vul_func)
		matched_bb_list_v_t = find_matched_bbs(s_v_bb, v_to_t, 1) # s_v_bb in target , return one with same hash.

	matched_bb_list_p_t = []
	if s_p:
		s_p_bb = add_list_to_bb_list(s_p, patch_func)
		matched_bb_list_p_t = find_matched_bbs(s_p_bb, p_to_t, 1)
	
	DIFF0 = False
	DIFF1 = False

	vul_vt = build_trace_graph_v2(diff_v_to_t[0] , s_v, vul_func) #T4
	print "get T4"
	patch_pt = build_trace_graph_v2(diff_p_to_t[0] , s_p, patch_func) #T6
	print "get T6"
	
	vul_vp = []
	patch_vp = []

	if diff[0]:
		vul_vp = build_trace_graph_v2(diff[0] , s_v, vul_func) #T1
		print "get T1"
	else:
		
		DIFF0 = True
	if diff[1]:
		patch_vp = build_trace_graph_v2(diff[1] , s_p, patch_func) #T2
		print "get T2"
	else:
		
		DIFF1 = True
	if matched_bb_list_p_t:
		tar_vt = build_trace_graph_v2(diff_v_to_t[1] , matched_bb_list_p_t, target_func) #T3
		cbb1 = set(diff_v_to_t[1])
		bbb1 = set(matched_bb_list_p_t).union(cbb1)
	else:
		tar_vt = build_trace_graph_v2(diff_v_to_t[1] , matched_bb_list_v_t, target_func) #T3
		cbb1 = set(diff_v_to_t[1])
		bbb1 = set(matched_bb_list_v_t).union(cbb1)
	print "get T3"
	
	if matched_bb_list_v_t:
		tar_pt = build_trace_graph_v2(diff_p_to_t[1] , matched_bb_list_v_t, target_func) #T5
		cbb2 = set(diff_p_to_t[1])
		bbb2 = set(matched_bb_list_v_t).union(cbb1)
	else:
		tar_pt = build_trace_graph_v2(diff_p_to_t[1] , matched_bb_list_p_t, target_func) #T5
		cbb2 = set(diff_p_to_t[1])
		bbb2 = set(matched_bb_list_p_t).union(cbb1)
	print "get T5"


	cbb = cbb1.union(cbb2)
	bbb = bbb1.union(bbb2)
	cbb_len = len(cbb)
	bbb_len = len(bbb)
	
	
	if vul_vt == -1 or patch_pt == -1 or vul_vp == -1 or patch_vp == -1 or tar_vt == -1 or tar_pt == -1:
		return "NA too much diff",[]


	tar_vt_reduced = []
	if not len(diff[1]) == 0:
		for trace in tar_vt:
			for taint_bb in diff[1]:
				if taint_bb in trace:
					tar_vt_reduced.append(trace)
	else:
		tar_vt_reduced = tar_vt

	tar_vt_reduced = tar_vt

	tar_pt_reduced = []
	if not len(diff[0]) == 0:
		for trace in tar_pt:
			for taint_bb in diff[0]:
				if taint_bb in trace:
					tar_pt_reduced.append(trace)
	else:
		tar_pt_reduced = tar_pt
	tar_pt_reduced = tar_pt
	

	if len(tar_vt_reduced) == 0 and len(tar_pt_reduced) == 0:
		return "NT no trace",[cbb_len,bbb_len]
	elif len(tar_vt_reduced) == 0:
		return "V no main changes",[cbb_len,bbb_len]
	elif len(tar_pt_reduced) == 0:
		return "P no main changes",[cbb_len,bbb_len]

	print "start get trace list"
	trace_list_vul_vp = get_instr_list(vul_func, vul_vp)
	trace_list_patch_vp = get_instr_list(patch_func, patch_vp)
	

	
	trace_list_vul_vt = get_instr_list(vul_func, vul_vt)
	
	trace_list_tar_vt = get_instr_list(target_func, tar_vt_reduced)
	
	trace_list_patch_pt = get_instr_list(patch_func, patch_pt)
	
	trace_list_tar_pt = get_instr_list(target_func, tar_pt_reduced)
	
	print "start matching"
	s_vt = matching_v2(trace_list_vul_vp, trace_list_tar_pt) #(T1,T5)
	s_pt = matching_v2(trace_list_patch_vp, trace_list_tar_vt) #(T2,T3)
	print "end matching"

	
	threshold = 0.5
	if not DIFF0 and not DIFF1:
		if s_vt > s_pt:
			return "V " + str(s_vt) + "/" + str(s_pt)  +" "+ str(len(diff_v_to_t[1])) + "/" + str(len(diff_p_to_t[1])),[cbb_len,bbb_len]
		if s_vt < s_pt:
			return "P " + str(s_vt) + "/" + str(s_pt) +" "+ str(len(diff_v_to_t[1])) + "/" + str(len(diff_p_to_t[1])),[cbb_len,bbb_len]
		else:
			return "C can't tell",[cbb_len,bbb_len]
	elif DIFF0:
		
		s_vt = matching_v2(trace_list_patch_vp, trace_list_patch_pt) #(T2,T6)
		s_pt = matching_v2(trace_list_patch_vp, trace_list_tar_vt) #(T2,T3)
		if s_vt > s_pt:
			return "V " + str(s_vt) + "/" + str(s_pt)  +" "+ str(len(diff_v_to_t[1])) + "/" + str(len(diff_p_to_t[1])),[cbb_len,bbb_len]
		if s_vt < s_pt:
			return "P " + str(s_vt) + "/" + str(s_pt) +" "+ str(len(diff_v_to_t[1])) + "/" + str(len(diff_p_to_t[1])),[cbb_len,bbb_len]
		else:
			return "C can't tell",[cbb_len,bbb_len]

	elif DIFF1:
		
		s_vt = matching_v2(trace_list_vul_vp, trace_list_tar_pt) #(T1,T5)
		s_pt = matching_v2(trace_list_vul_vp, trace_list_vul_vt) #(T1,T4)
		if s_vt > s_pt:
			return "V " + str(s_vt) + "/" + str(s_pt)  +" "+ str(len(diff_v_to_t[1])) + "/" + str(len(diff_p_to_t[1])),[cbb_len,bbb_len]
		if s_vt < s_pt:
			return "P " + str(s_vt) + "/" + str(s_pt) +" "+ str(len(diff_v_to_t[1])) + "/" + str(len(diff_p_to_t[1])),[cbb_len,bbb_len]
		else:
			return "C can't tell",[cbb_len,bbb_len]
	


def read_exp_config():
	record_list = []
	
	with open(r'F:\everything\binary_exp\freetype\freetype_config.csv', 'rb') as csvfile:
		r = csv.reader(csvfile, delimiter=',')
		for row in r:
			if len(row) >= 4:
				#TODO: discard the cve id info for now
				base = [row[1],row[2],row[0]]
				
				for x in range(3, len(row)):
					if row[x]:
						item = row[x]
						item = item.replace("*","")
						item = item.strip()

						tmp = [item]
						tmp.extend(base)
						record_list.append(tmp)
	
	return record_list


def controler(n_v):
	config = read_exp_config()
	config = set(tuple(row) for row in config)
	
	result = []
	cost = 0
	func_count = 0
	cbb = 0
	bbb = 0
	b_count = 0
	f_bb = 0
	f_count = 0
	for record in config:
		CVE_id = record[3]
		function_name = record[0]
		patch_version = record[2]
		vul_version = record[1]

		list_head = [CVE_id,function_name, patch_version, vul_version]
		
		tmp,time,bb,f = run_one_exp(function_name, vul_version, patch_version)
		
		if len(tmp) == n_v:
			list_head.extend(tmp)
			result.append(list_head)
			cost += time[0]
			func_count += time[1]
			cbb += bb[0]
			bbb += bb[1]
			b_count += bb[2]
			f_bb += f[0]
			f_count += f[1]
	print "cost:",cost
	print "func_count:",func_count
	print "one func time:",cost / float(func_count)
	print "cbb:",cbb
	print "bbb:",bbb
	print "b_count:",b_count
	if b_count != 0:
		print "avr_cbb:",float(cbb)/float(b_count)
		print "avr_cbb+bbb:",float(bbb)/float(b_count)
	else:
		print "avr_cbb:",0
		print "avr_cbb+bbb:",0
	print "f_bb:",f_bb
	print "f_count:",f_count
	print "avr_bb",float(f_bb) / float(f_count)
	return result

	
def read_versions():
	version_list = []
	with open(r'F:\everything\binary_exp\freetype\freetype_version.csv', 'rb') as csvfile:
		r = csv.reader(csvfile, delimiter=',')
		for row in r:
			if len(row) == 1:
				version_list.append(row[0])
	return version_list
	
def run_one_exp(function_name, vul_version, patch_version):
	print "analysing " + function_name
	
	
	sig = extract_sig(function_name, vul_version, patch_version) #sig includes [vul_func, patch_func, diff]
	
	if not sig:
		return ["ERROR"],[],[],[]
	
	version_list = read_versions()
	result_list = []
	cost = 0
	count = 0
	cbb = 0
	bbb = 0
	b_count = 0
	f_bb = 0
	f_count = 0
	for version in version_list:
		
		target_func = load_target_func(function_name, version)
		if not target_func:
			result_list.append("NA")
			continue
		f_bb += len(target_func.bbs)
		f_count += 1
		
		start = time.time()
		decision,bb_len = match_decision(target_func, sig)
		end = time.time()
		cost += (end - start)
		count += 1
		if bb_len:
			b_count += 1
			cbb += bb_len[0]
			bbb += bb_len[1]
		print "decision:",decision
		result_list.append(decision)
	return result_list,[cost,count],[cbb,bbb,b_count],[f_bb,f_count]

def calculate_acc(raw_result):
	acc = 0
	count = 0
	good_count = 0
	total_good = 0
	total_bad = 0
	no_diff_count = 0
	good_list_name = "good_list.csv"
	bad_list_name = "bad_list.csv"
	good_list = []
	bad_list = []
	vers = read_versions()
	all_ver = {}
	too_much_diff = 0
	for i in range(len(vers)):
		all_ver[vers[i]] = i+1
	
	for item in raw_result:
		p_ver = all_ver[item[2]]
		
		count += 1
		flag = True
		no_diff = False
		
		for i in range(4, len(item)):
			
			if (i-3) < p_ver:
				if item[i].split(' ')[0] == "V":
					total_good += 1
					continue
				elif item[i].split(' ')[0] == "N" and item[i] != "NA":
					no_diff_count += 1
					flag = False
					continue

				elif item[i] == "NA too much diff":
					too_much_diff += 1
					continue

				if not (item[i].split(' ')[0] == "V" or item[i] == "NA"):
					flag = False
					#break
					total_bad += 1 
			else:
				if item[i].split(' ')[0] == "P":
					total_good += 1
					continue
				elif item[i].split(' ')[0] == "N" and item[i] != "NA":
					no_diff_count += 1
					flag = False
					continue

				elif item[i] == "NA too much diff":
					too_much_diff += 1
					continue

				if not (item[i].split(' ')[0] == "P" or item[i] == "NA"):
					flag = False
					#break
					total_bad += 1
		

		if flag:
			good_count += 1
			good_list.append(item)
		else:
			bad_list.append(item)

	
	print "count"
	print count
	print "good_count"
	print good_count
	print "total_good"
	print total_good
	print "total_bad"
	print total_bad
	print "no_diff_count"
	print no_diff_count
	print "too_much_diff"
	print too_much_diff

	for item in bad_list:
		print item
	

def cal_v2(res,cve,gt): #gt = {cve:p_ver}
	cve_good = 0
	cve_bad = 0
	all_ver = {}
	vers = read_versions()
	for i in range(len(vers)):
		all_ver[vers[i]] = i+1
	for ver in range(1,len(all_ver)+1):
		
		cve_res = get_cve_res(res,cve,ver+3)
		
		for cve_id in gt:
			if ver < all_ver[gt[cve_id]]:
				if cve_res[cve_id] == 'V':
					cve_good += 1
				if cve_res[cve_id] == 'P':
					cve_bad += 1
			else:
				if cve_res[cve_id] == 'P':
					cve_good += 1
				if cve_res[cve_id] == 'V':
					cve_bad += 1
	
	print "cve_good"
	print cve_good
	print "cve_bad"
	print cve_bad
			

def main():
	pass

def unit_test(out,n_v):
	
	 
	r = controler(n_v)
	for rr in r:
		print "rr:",rr
	
	with open(out,'w') as f:
		json.dump(r, f)
	

def calculate(out):
	with open(out,'rb')as f:
		r = json.load(f)
	cve_file = r'F:\everything\vmlinux_config.csv'
	cve = {}
	with open(cve_file, 'rb') as csvfile:
		r = csv.reader(csvfile, delimiter=',')
		for row in r:
			if len(row) >= 4:
				cve_id = row[0]
				if cve_id not in cve:
					cve[cve_id] = []
				for x in range(3, len(row)):
					if row[x]:
						item = row[x]
						item = item.replace("*","")
						item = item.strip()
						cve[cve_id].append(item)
	cve_res,func_res,cve = get_cve_res(r,cve)
	gt_file = r'F:\everything\gt.csv'
	good,bad,total_good,total_bad,no_diff,cant_tell = calculate_acc_v2(func_res,cve,cve_res,gt_file)
	print "good:",good
	print "bad:",bad
	print "total_good:",total_good
	print "total_bad:",total_bad
	print "no_diff:",no_diff
	print "cant_tell:",cant_tell

def get_cve_res(results,cve,ver): #cve = {cve_id:[func_list]}
	func_res = {}
	cve_res = {}
	for r in results:
		cve_id = r[0]
		func_name = r[1]
		res = r[ver][0]
		if func_name not in func_res:
			func_res[func_name] = {}
		if res == 'V':
			func_res[func_name][cve_id] = 'V'
		elif res == 'P':
			func_res[func_name][cve_id] = 'P'
		elif res == 'C':
			func_res[func_name][cve_id] = 'C'
		else :
			func_res[func_name][cve_id] = 'N'
	
	for c in cve:
		if len(cve[c]) == 1:
			if cve[c][0] not in func_res:
				cve_res[c] = 'N'
				continue
			cve_res[c] = func_res[cve[c][0]][c]
		else:
			vc = 0
			pc = 0
			nc = 0
			for f in cve[c]:
				if f not in func_res:
					nc += 1
					continue
				if func_res[f][c] == 'V':
					vc += 1
				if func_res[f][c] == 'P':
					pc += 1
				if func_res[f][c] == 'N' or func_res[f][c] == 'C':
					nc += 1
			if vc == 0 and pc == 0:
				cve_res[c] = 'N'
			elif vc >=2 or pc <= vc:
				cve_res[c] = 'V'
			elif nc == len(cve[c]):
				cve_res[c] = 'N'
			else:
				cve_res[c] = 'P'
	return cve_res

def calculate_acc_v2(func_res,cve,cve_res,gt_file): #gt = {cve_id:v/p}
	gt = {}
	good = 0
	bad = 0
	total_good = 0
	total_bad = 0
	no_diff = 0
	cant_tell = 0
	with open(gt_file, 'rb') as csvfile:
		r = csv.reader(csvfile, delimiter=',')
		for row in r:
			cve_id = row[0]
			gt[cve_id] = row[1]
	for c in cve_res:
		if cve_res[c] == gt[c]:
			good += 1
		else:
			bad += 1
	for c in gt:
		for f in cve[c]:
			if f not in func_res:
				continue
			if func_res[f][c] == gt[c]:
				total_good += 1
			else:
				total_bad += 1
			if func_res[f][c] == "N":
				no_diff += 1
			if func_res[f][c] == "C":
				cant_tell += 1

	return good,bad,total_good,total_bad,no_diff,cant_tell


if __name__ == '__main__':
	#main()
	out = r'F:\everything\binary_exp\freetype\out2.json'
	unit_test(out,19)
	with open(out,'rb')as f:
		res = json.load(f)
	calculate_acc(res)
	cve_file = r'F:\everything\binary_exp\freetype\freetype_config.csv'
	cve = {}
	gt = {}
	with open(cve_file, 'rb') as csvfile:
		r = csv.reader(csvfile, delimiter=',')
		for row in r:
			if len(row) >= 4:
				cve_id = row[0]
				p_ver = row[2]
				if cve_id not in cve:
					cve[cve_id] = []
					gt[cve_id] = p_ver
				for x in range(3, len(row)):
					if row[x]:
						item = row[x]
						item = item.replace("*","")
						item = item.strip()
						cve[cve_id].append(item)
		cal_v2(res,cve,gt)
