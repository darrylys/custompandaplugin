Plugin: dypandasok
==================


Summary
-------

This plugin is to generate somewhat similar image report of packerinspector. See the following paper:
* Ugarte-Pedrero, X., Balzarotti, D., Santos, I., & Bringas, P. G. (2015, May). SoK: Deep packer inspection: A longitudinal study of the complexity of run-time packers. In 2015 IEEE Symposium on Security and Privacy (pp. 659-673). IEEE.

This plugin has two components, the PANDA one and the image generator python script. The PANDA one will generate a report in json format with name dypandasok.log.
To generate the image report, use the ./generator/generategraph.py script. The image is generated with name dypandasok.log.png.
Output file names cannot be configured.


Dependencies
------------

Library:
--------
	`capstone` disassembler
	
Plugins:
--------
	osi
	syscalls2				: For hooking on memory manipulation system calls
	wintrospection
	my_callstack_instr		: A little enhancement over callstack_instr to allow analyzing only on some asids / pids.
	win7x86intro
	dyremoteprocwrite		: Monitoring remote write
	dywin7x86sp1apilogger

Generator script python modules:
--------------------------------
	python 3
    pydot
    graphviz
    json      (should be default)
    bisect    (should be default)


Arguments
---------

	`asid-csv`		: pipe-character separated list of process cr3 to analyze (required)
	`pid-csv`		: pipe-character separated list of process pid to analyze (required)
	`start-addr`	: start analysis address in hex (default 0)
	`end-addr`		: end analysis address in hex, excluded. The analysis address to be analyzed satisfies: `start-addr <= addr < end-addr` (default 0x10000000)
	`only-from-app`	: only records api calls from module, not counting dll to dll. (default false)


API and callbacks
-----------------

None


Example
-------

	i386-softmmu/qemu-system-i386 \
		-replay obsidium1250f \
		-m 2G \
		-monitor stdio \
		-panda 'my_callstack_instr:prog_list=pid-int(|pid-int)*' \
		-panda 'syscalls2' \
		-panda dyremoteprocwrite \
		-panda dywin7x86sp1apilogger:apicsv=/home/.../panda/plugins/dywin7x86sp1apilogger/res/db-fn.csv,typecsv=/home/.../panda/plugins/dywin7x86sp1apilogger/res/db-types.csv,use_as_db=true' \
		-panda 'dypandasok:asid-csv=hex-asid(|hex-asid)*,pid-csv=pid-int(|pid-int)*' \
		-os 'windows-32-7'

asid-csv can contain pipe (`|`) separated hex-asid string value, and likewise, the pid-csv can contain pipe (`|`) separated int value.
Asid and PID of i-th process are described in i-th element in asid-csv and pid-csv array.


Limitations
-----------

Plugin limitations:
	Only available for Windows 7 x86
	The generator python script reads whole json file into memory, processing all of those into a graph, and may consume a lot of memory (~2GB)
	Cannot handle API obfuscation technique, in particular: code stealing. This is observed in Obsidium 12f
	Sometimes, the execution address is wrong, although it returned correctly later on. This is not this plugins' fault but more of qemu error. Observed in Exeshield 3.7
	
Limitations from dyremoteprocwrite plugin:
	No support for Atom Bombing
	No support for process write via external Files / Streams
	Limited support for process writes via shared memory
	Limited support for process writes via shared File Mapping

QEMU emulation issue:
	QEMU in x86 does not support 0xF1 instruction. In native, this throws SINGLE_STEP exception. In Qemu, however, this throws ILLEGAL_INSTRUCTION exception
	QEMU does not handle prefix 0xf0 correctly. If done incorrectly, this throws ILLEGAL_INSTRUCTION exception. In qemu, this does nothing. (Found in Armadillo 4.30a)
    e.g. F0 90 (LOCK NOP) throws EXCEPTION_ILLEGAL_INSTRUCTION on native Intel, but no exception is thrown in QEMU.



