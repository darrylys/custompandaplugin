PLUGIN: dyevdtnopseq
======


Summary:
------

This plugin checks for sequence of NOP in translation block.
The output is written to dyevdtnopseq.report.log file. 
Format is `<instrcnt> <guest address of start of sequence> <length of sequence>`


Arguments:
---------

* `asid`	: the asid of the process to analyze
* `nopsize`	: the NOP window size. Plugin will report the sequence with length gte this parameter.


Dependencies:
------------

None


Example:
-------

`i386-softmmu/qemu-system-i386 -m 2G -monitor stdio -replay manynops -panda 'dyevdtnopseq:asid=7ec5000' -os 'windows-32-7'`

Limitations:
-----------

Only available for Windows 7 x86 for now.
