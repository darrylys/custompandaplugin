PLUGIN: exectrace
=================


Summary:
------

A plugin do trace execution of a program. This plugin does not trace libraries and kernels. Output disassembly of execution with the registry values are in file exectrace.log. Output file cannot be configured.


Arguments:
---------

* `asid`	: the asid of the process to analyze


Dependencies:
------------

Library dependency:
	capstone

Plugin dependency:
	None

Example:
-------

`i386-softmmu/qemu-system-i386 -m 2G -monitor stdio -replay xxx -panda 'exectrace:asid=1b65e000' -os windows-32-7`


Limitations:
-----------

Only available for Windows 7 x86


