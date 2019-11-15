PLUGIN: dyevdtntglobalflag
======


Summary:
------

This plugin is unfinished.
This plugin attempts to find out whether a program checks the value of NtGlobalFlag
in PEB structure or not.
The output is written to dyevdtntglobalflag.report.log file. 


Arguments:
---------

* `asid`	: the asid of the process to analyze


Dependencies:
------------

`taint2` plugin


Example:
-------

i386-softmmu/qemu-system-i386 \
		-m 2G \
		-replay xxx \
		-monitor stdio \
		-panda 'taint2:max_taintset_compute_number=2,max_taintset_card=2;dyevdtntglobalflag:asid=5368000' \
		-os 'windows-32-7'


Limitations:
-----------

Only available for Windows 7 x86
