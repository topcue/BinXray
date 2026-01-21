import os
from subprocess import Popen

def main():
	
	all_file_list = os.listdir(r'F:\everything\d_link\bin')
	file_list = []
	for f in all_file_list:
		if ('.i64' not in f) and ('idb' not in f) :
			file_list.append(f)
	
	for item in file_list:
		
		tmp = item
		
		tmp = r"F:\everything\d_link\bin" +'\\'+ tmp
		
		
		scritp_address = r"F:\everything\extract.py"
		
		
		popen_command = "\"D:\\IDA 6.8\\idaq.exe\" -A -B -L\"F:\\everything\\d_link\\error3.txt\" -S" + '\"'+ scritp_address+'\"'+ " " + tmp
		print popen_command
		
		
		p = Popen(popen_command)
		stdout, stderr = p.communicate()
		
	
if __name__ == '__main__':
	main()