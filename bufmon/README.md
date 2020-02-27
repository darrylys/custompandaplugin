Plugin: bufmon
==============

Summary
-------
This is a plugin ported from PANDA1 bufmon, as well as some changes of my own.

The `bufmon` plugin tracks all memory accesses to a particular buffer throughout a replay.

Takes a single input file, `search_buffers.txt`, with the buffers to monitor, one per line in the file. Each buffer is specified by its starting virtual address, size, and address space (all in hexadecimal).

Produces a single output file, `buffer_taps.txt`. Each line gives an indicator of whether the access was a read or a write (`READ` or `WRITE`), the guest instruction count, tap point, virtual address accessed, size of the access, and finally the actual bytes that were read or written.


Dependencies
------------
This plugin requires `callstack_instr` plugin. Due to some changes to `callstack_instr` plugin, if no argument is given, `callstack_instr` will assume `stack_type=threaded` on Windows platforms which is not the old `callstack_instr` behavior when bufmon is developed. To use `callstack_instr` old behavior, add parameter `stack_type=asid` to it.


APIs and Callbacks
------------------

None.

Example
-------

To monitor the buffer at `0x10000` of size `0x10` bytes in ASID `0x3f9b2040`, you would create a `search_buffers.txt` that looks like:

    10000 10 3f9b2040

And then run:

For unknown OS:
    `$PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo -panda 'callstack_instr' -panda bufmon`

For Windows:
    `$PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo -panda 'callstack_instr:stack_type=asid' -panda bufmon -os 'windows-32-7'`


Sample Output
-------------
    A 1d659000 --> 07f9b000 (Asid changes `old_asid`, `new_asid`)
    R 78551462 p.caller=77347525 p.pc=7733f5f0 p.cr3=07f9b000 addr=0040003c size=00000004 pid=892 tid=1572 in_kernel=0 pc=7733f5f0 current_asid=07f9b000 f0 00 00 00 | . . . . (Read operations)
    W 79441062 p.caller=77344e8e p.pc=7733f854 p.cr3=07f9b000 addr=0040209c size=00000004 pid=892 tid=1572 in_kernel=0 pc=7733f854 current_asid=07f9b000 10 09 f9 6c | . . . l (Write operations)

