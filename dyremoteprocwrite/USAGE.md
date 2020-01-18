Plugin: dyremoteprocwrite
=========================

Summary
-------

This plugin sends notification when a process is writing to another process. Only tested for Windows 7 x86.
This plugin monitors writes to different process by monitoring syscall, in particular: NtWriteVirtualMemory, NtOpenSection, NtCreateSection, NtMapViewOfSection and NtUnmapViewOfSection.
As this plugin does not print any report, it is not useful on its own.


Dependencies
------------

This plugin depends on the following plugins:
	osi
	syscalls2
	wintrospection
	my_callstack_instr
	win7x86intro
	asidstory


Arguments
---------

None



API and callbacks
-----------------

typedef void (*on_remote_write_ex_t)(REMOTE_WRITE* remote_write);
The contents of structure REMOTE_WRITE is described in common_types.h



Limitations
-----------

Since this plugin monitors writes via limited set of syscalls, it is unable to monitor more sophisticated methods such as:
	Atom bombing via GlobalGetAtom
	Read/writes via filesystem




