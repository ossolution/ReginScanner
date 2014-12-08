/* Scroll down to find a YARA rule set to detect Regin Backdoor samples

Update 06.12.14 11:00
New False Positives SHA256s and Updated Yara rule "Regin_Sample_1"
a26db2eb9f3e2509b4eba949db97595cc32332d9321df68283bfc102e66d766f - Windows Serial Driver
18cd54d163c9c5f16e824d13c411e21fd7616d34e9f1cf2adcbf869ed6aeeed4 - CD Tower Web Client

Update 03.12.14 18:10
Updated false positives

Update 02.12.14 09:15
Added new and yet unknown Regin sample found via Virustotal with SHA256
627dc5599c28de3c494496399b39f3aac7049586e72cbdb08bea01bf40166c23

Update 28.11.14 14:00
False Positive detected. Microsoft XP USB Scanner Driver. See false positive hash list below.
Updated rule "Regin_APT_KernelDriver_Generic_B" to exclude string that appears in Windows XP usb scanner driver. 

Update 28.11.14 09:00
Check out ReginScanner to scan for multiple IOCs at once. It does not ship with the Kaspersky Yara rules. You should include them manually. (see the link below)
https://github.com/Neo23x0/ReginScanner

Update 27.11.14
I added a new signature set targeting new samples or samples that were not detected by the generic rules.

Tested on:
- Windows 7 x64
- Windows 2003
- Windows 2008 R2

False Positives:
The signatures are known to generate False Positives on certain Windows XP USB scanner drivers. (see list below for hashes)

Please check back with an MD5/SHA1/SHA256 hash if you found a sample that has Antivirus hits and is not in this list.

Known sample list - SHA256:
20831e820af5f41353b5afab659f2ad42ec6df5d9692448872f3ed8bbb40ab92
225e9596de85ca7b1025d6e444f6a01aa6507feef213f4d2e20da9e7d5d8e430
392f32241cd3448c7a435935f2ff0d2cdc609dda81dd4946b1c977d25134e96e
40c46bcab9acc0d6d235491c01a66d4c6f35d884c19c6f410901af6d1e33513b
4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be
4e39bc95e35323ab586d740725a1c8cbcde01fe453f7c4cac7cced9a26e42cc9
5001793790939009355ba841610412e0f8d60ef5461f2ea272ccf4fd4c83b823
5c81cf8262f9a8b0e100d2a220f7119e54edfc10c4fb906ab7848a015cd12d90
627dc5599c28de3c494496399b39f3aac7049586e72cbdb08bea01bf40166c23
7553d4a5914af58b23a9e0ce6a262cd230ed8bb2c30da3d42d26b295f9144ab7
7d38eb24cf5644e090e45d5efa923aff0e69a600fb0ab627e8929bb485243926
8098938987e2f29e3ee416b71b932651f6430d15d885f2e1056d41163ae57c13
8389b0d3fb28a5f525742ca2bf80a81cf264c806f99ef684052439d6856bc7e7
8d7be9ed64811ea7986d788a75cbc4ca166702c6ff68c33873270d7c6597f5db
﻿9cd5127ef31da0e8a4e36292f2af5a9ec1de3b294da367d7c05786fe2d5de44f
9ddbe7e77cb5616025b92814d68adfc9c3e076dddbe29de6eb73701a172c3379
a0d82c3730bc41e267711480c8009883d1412b68977ab175421eabc34e4ef355
a0e3c52a2c99c39b70155a9115a6c74ea79f8a68111190faa45a8fd1e50f8880
a6603f27c42648a857b8a1cbf301ed4f0877be75627f6bbe99c0bfd9dc4adb35
a7493fac96345a989b1a03772444075754a2ef11daa22a7600466adc1f69a669
a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe
a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe
b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047
b755ed82c908d92043d4ec3723611c6c5a7c162e78ac8065eb77993447368fce
c0cf8e008fbfa0cb2c61d968057b4a077d62f64d7320769982d28107db370513
cca1850725f278587845cd19cbdf3dceb6f65790d11df950f17c5ff6beb18601
df77132b5c192bd8d2d26b1ebb19853cf03b01d38afd5d382ce77e0d7219c18c
e1ba03a10a40aab909b2ba58dcdfd378b4d264f1f4a554b669797bbb8c8ac902
e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935
ecd7de3387b64b7dab9a7fb52e8aa65cb7ec9193f8eac6a7d79407a6a932ef69
f1d903251db466d35533c28e3c032b7212aa43c8d64ddf8c5521b43031e69e1e
f89549fc84a8d0f8617841c6aa4bb1678ea2b6081c1f7f74ab1aebd4db4176e4
fd92fd7d0f925ccc0b4cbb6b402e8b99b64fa6a4636d985d78e5507bd4cfecef
fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129

Heavily encrypted - use Hash instead of a Yara rule to detect these samples:
d42300fea6eddcb2f65ffec9e179e46d87d91affad55510279ecbb0250d7fdff

Known False Positives:
6e5ebbc8b70c1d593634daf0c190deadfda18c3cbc8f552a76f156f3869ef05b - Microsoft USB Scanner Driver
7565e7de9532c75b3a16e3ed0103bc092dbca63c6bdc19053dfef01250029e59 - NSRL listed
a26db2eb9f3e2509b4eba949db97595cc32332d9321df68283bfc102e66d766f - Windows Serial Driver
18cd54d163c9c5f16e824d13c411e21fd7616d34e9f1cf2adcbf869ed6aeeed4 - CD Tower Web Client

Please check out this URL for the Kaspersky report with more specific Yara rules: 
https://securelist.com/files/2014/11/Kaspersky_Lab_whitepaper_Regin_platform_eng.pdf 
*/

rule Regin_APT_KernelDriver_Generic_A {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "187044596bc1328efa0ed636d8aa4a5c"
		hash2 = "06665b96e293b23acc80451abb413e50"
		hash3 = "d240f06e98c8d3e647cbf4d442d79475"
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
		$m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		
		$s0 = "atapi.sys" fullword wide
		$s1 = "disk.sys" fullword wide
		$s3 = "h.data" fullword ascii
		$s4 = "\\system32" fullword ascii
		$s5 = "\\SystemRoot" fullword ascii
		$s6 = "system" fullword ascii
		$s7 = "temp" fullword ascii
		$s8 = "windows" fullword ascii

		$x1 = "LRich6" fullword ascii
		$x2 = "KeServiceDescriptorTable" fullword ascii		
	condition:
		$m0 at 0 and $m1 and  	
		all of ($s*) and 1 of ($x*)
}

rule Regin_APT_KernelDriver_Generic_B {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "ffb0b9b5b610191051a7bdf0806e1e47"
		hash2 = "bfbe8c3ee78750c3a520480700e440f8"
		hash3 = "b29ca4f22ae7b7b25f79c1d4a421139d"
		hash4 = "06665b96e293b23acc80451abb413e50"
		hash5 = "2c8b9d2885543d7ade3cae98225e263b"
		hash6 = "4b6b86c7fec1c574706cecedf44abded"
		hash7 = "187044596bc1328efa0ed636d8aa4a5c"
		hash8 = "d240f06e98c8d3e647cbf4d442d79475"
		hash9 = "6662c390b2bbbd291ec7987388fc75d7"
		hash10 = "1c024e599ac055312a4ab75b3950040a"
		hash11 = "ba7bb65634ce1e30c1e5415be3d1db1d"
		hash12 = "b505d65721bb2453d5039a389113b566"
		hash13 = "b269894f434657db2b15949641a67532"
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
		$s1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		$s2 = "H.data" fullword ascii nocase
		$s3 = "INIT" fullword ascii
		$s4 = "ntoskrnl.exe" fullword ascii
		
		$v1 = "\\system32" fullword ascii
		$v2 = "\\SystemRoot" fullword ascii
		$v3 = "KeServiceDescriptorTable" fullword ascii	
		
		$w1 = "\\system32" fullword ascii
		$w2 = "\\SystemRoot" fullword ascii		
		$w3 = "LRich6" fullword ascii
		
		$x1 = "_snprintf" fullword ascii
		$x2 = "_except_handler3" fullword ascii
		
		$y1 = "mbstowcs" fullword ascii
		$y2 = "wcstombs" fullword ascii
		$y3 = "KeGetCurrentIrql" fullword ascii
		
		$z1 = "wcscpy" fullword ascii
		$z2 = "ZwCreateFile" fullword ascii
		$z3 = "ZwQueryInformationFile" fullword ascii
		$z4 = "wcslen" fullword ascii
		$z5 = "atoi" fullword ascii

		$fp1 = "\\\\.\\Usbscan" wide fullword
	condition:
		$m0 at 0 and all of ($s*) and 
		( all of ($v*) or all of ($w*) or all of ($x*) or all of ($y*) or all of ($z*) ) 
		and filesize < 20KB
		and not $fp1
}

rule Regin_APT_KernelDriver_Generic_C {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "e0895336617e0b45b312383814ec6783556d7635"
		hash2 = "732298fa025ed48179a3a2555b45be96f7079712"		
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
	
		$s0 = "KeGetCurrentIrql" fullword ascii
		$s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		$s2 = "usbclass" fullword wide
		
		$x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
		$x2 = "Universal Serial Bus Class Driver" fullword wide
		$x3 = "5.2.3790.0" fullword wide
		
		$y1 = "LSA Shell" fullword wide
		$y2 = "0Richw" fullword ascii		
	condition:
		$m0 at 0 and all of ($s*) and 
		( all of ($x*) or all of ($y*) ) 
		and filesize < 20KB
}

/* Update 27.11.14 */

rule Regin_sig_svcsstat {
	meta:
		description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"
	strings:
		$s0 = "Service Control Manager" fullword ascii
		$s1 = "_vsnwprintf" fullword ascii
		$s2 = "Root Agency" fullword ascii
		$s3 = "Root Agency0" fullword ascii
		$s4 = "StartServiceCtrlDispatcherA" fullword ascii
		$s5 = "\\\\?\\UNC" fullword wide
		$s6 = "%ls%ls" fullword wide
	condition:
		all of them and filesize < 15KB and filesize > 10KB 
}

rule Regin_Sample_1 {
	meta:
		description = "Auto-generated rule - file-3665415_sys"
		author = "Florian Roth"
		date = "06.12.14"
		hash = "773d7fab06807b5b1bc2d74fa80343e83593caf2"
	strings:
		$s0 = "Getting PortName/Identifier failed - %x" fullword ascii
		$s1 = "SerialAddDevice - error creating new devobj [%#08lx]" fullword ascii
		$s2 = "External Naming Failed - Status %x" fullword ascii
		$s3 = "------- Same multiport - different interrupts" fullword ascii
		$s4 = "%x occurred prior to the wait - starting the" fullword ascii
		$s5 = "'user registry info - userPortIndex: %d" fullword ascii
		$s6 = "Could not report legacy device - %x" fullword ascii
		$s7 = "entering SerialGetPortInfo" fullword ascii
		$s8 = "'user registry info - userPort: %x" fullword ascii
		$s9 = "IoOpenDeviceRegistryKey failed - %x " fullword ascii
		$s10 = "Kernel debugger is using port at address %X" fullword ascii
		$s12 = "Release - freeing multi context" fullword ascii
		$s13 = "Serial driver will not load port" fullword ascii
		$s14 = "'user registry info - userAddressSpace: %d" fullword ascii
		$s15 = "SerialAddDevice: Enumeration request, returning NO_MORE_ENTRIES" fullword ascii
		$s20 = "'user registry info - userIndexed: %d" fullword ascii

		$fp1 = "Enter SerialBuildResourceList" ascii fullword
	condition:
		all of them and filesize < 110KB and filesize > 80KB and not $fp1
}

rule Regin_Sample_2 {
	meta:
		description = "Auto-generated rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "a7b285d4b896b66fce0ebfcd15db53b3a74a0400"
	strings:
		$s0 = "\\SYSTEMROOT\\system32\\lsass.exe" fullword wide
		$s1 = "atapi.sys" fullword wide
		$s2 = "disk.sys" fullword wide
		$s3 = "IoGetRelatedDeviceObject" fullword ascii
		$s4 = "HAL.dll" fullword ascii
		$s5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" fullword ascii
		$s6 = "PsGetCurrentProcessId" fullword ascii
		$s7 = "KeGetCurrentIrql" fullword ascii
		$s8 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s9 = "KeSetImportanceDpc" fullword ascii
		$s10 = "KeQueryPerformanceCounter" fullword ascii
		$s14 = "KeInitializeEvent" fullword ascii
		$s15 = "KeDelayExecutionThread" fullword ascii
		$s16 = "KeInitializeTimerEx" fullword ascii
		$s18 = "PsLookupProcessByProcessId" fullword ascii
		$s19 = "ExReleaseFastMutexUnsafe" fullword ascii
		$s20 = "ExAcquireFastMutexUnsafe" fullword ascii
	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_3 {
	meta:
		description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		author = "@Malwrsignatures"
		date = "27.11.14"
		hash = "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"		
	strings:
		$hd = { fe ba dc fe }
	
		$s0 = "Service Pack x" fullword wide
		$s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
		$s2 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" fullword wide
		$s3 = "mntoskrnl.exe" fullword wide
		$s4 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" fullword wide
		$s5 = "Memory location: 0x%p, size 0x%08x" wide fullword
		$s6 = "Service Pack" fullword wide
		$s7 = ".sys" fullword wide
		$s8 = ".dll" fullword wide		
		
		$s10 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Updates" fullword wide
		$s11 = "IoGetRelatedDeviceObject" fullword ascii
		$s11 = "VMEM.sys" fullword ascii
		$s12 = "RtlGetVersion" fullword wide
		$s14 = "ntkrnlpa.exe" fullword ascii
	condition:
		( $hd at 0 ) and all of ($s*) and filesize > 160KB and filesize < 200KB
}

rule Regin_Sample_Set_1 {
	meta:
		description = "Auto-generated rule - file SHF-000052 and ndisips.sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "8487a961c8244004c9276979bb4b0c14392fc3b8"
		hash = "bcf3461d67b39a427c83f9e39b9833cfec977c61"		
	strings:
		$s0 = "HAL.dll" fullword ascii
		$s1 = "IoGetDeviceObjectPointer" fullword ascii
		$s2 = "MaximumPortsServiced" fullword wide
		$s3 = "KeGetCurrentIrql" fullword ascii
		$s4 = "ntkrnlpa.exe" fullword ascii
		$s5 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s6 = "ConnectMultiplePorts" fullword wide
		$s7 = "\\SYSTEMROOT" fullword wide
		$s8 = "IoWriteErrorLogEntry" fullword ascii
		$s9 = "KeQueryPerformanceCounter" fullword ascii
		$s10 = "KeServiceDescriptorTable" fullword ascii
		$s11 = "KeRemoveEntryDeviceQueue" fullword ascii
		$s12 = "SeSinglePrivilegeCheck" fullword ascii
		$s13 = "KeInitializeEvent" fullword ascii
		$s14 = "IoBuildDeviceIoControlRequest" fullword ascii
		$s15 = "KeRemoveDeviceQueue" fullword ascii
		$s16 = "IofCompleteRequest" fullword ascii
		$s17 = "KeInitializeSpinLock" fullword ascii
		$s18 = "MmIsNonPagedSystemAddressValid" fullword ascii
		$s19 = "IoCreateDevice" fullword ascii
		$s20 = "KefReleaseSpinLockFromDpcLevel" fullword ascii
	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_Set_2 {
	meta:
		description = "Detects Regin Backdoor sample 4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be and e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
		author = "@MalwrSignatures"
		date = "27.11.14"
		hash = "4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be"
		hash = "e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
	strings:
		$hd = { fe ba dc fe }
	
		$s0 = "d%ls%ls" fullword wide
		$s1 = "\\\\?\\UNC" fullword wide
		$s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide
		$s3 = "\\\\?\\UNC\\" fullword wide
		$s4 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
		$s5 = "System\\CurrentControlSet\\Services\\Tcpip\\Linkage" wide fullword
		$s6 = "\\\\.\\Global\\%s" fullword wide
		$s7 = "temp" fullword wide
		$s8 = "\\\\.\\%s" fullword wide
		$s9 = "Memory location: 0x%p, size 0x%08x" fullword wide		
		
		$s10 = "sscanf" fullword ascii
		$s11 = "disp.dll" fullword ascii
		$s11 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii
		$s12 = "%d.%d.%d.%d%c" fullword ascii
		$s13 = "imagehlp.dll" fullword ascii
		$s14 = "%hd %d" fullword ascii
	condition:
		( $hd at 0 ) and all of ($s*) and filesize < 450KB and filesize > 360KB
}