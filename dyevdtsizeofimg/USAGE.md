PLUGIN: dyevdtsizeofimg
======


Summary:
------

This plugin checks whether the analyzed program writes to SizeOfImage in LDR_DATA_TABLE_ENTRY or not.
Overwriting SizeOfImage is common technique employed to disrupt executable memory dumping.
The output is written to dyevdtsizeofimg.report.log file. 
Sample of output:
...
ORIGINAL 0000000000301880 00005000			: this is the guest address and original value of the SizeOfImage parameter
64634879 W 0000000000301880 4 009f0000		: this is the modification attempt by program. Format: <instrcnt> W <guest address> <write size> <new value>

Arguments:
---------

* `asid`	: the asid of the process to analyze


Dependencies:
------------

None


Example:
-------

`i386-softmmu/qemu-system-i386 -m 2G -monitor stdio -replay xxx -panda 'dyevdtsizeofimg:asid=1b65e000' -os windows-32-7`


Limitations:
-----------

Only available for Windows 7 x86
