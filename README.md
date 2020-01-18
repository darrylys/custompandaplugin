Custom panda plugins
====================

Summary
-------

These are some customized PANDA (https://github.com/panda-re/panda) plugins that is developed for my project  
These are not always up-to-date with latest PANDA  
Only tested on Windows 7 x86  


Workflow
--------

This is the workflow that I came up with for malware analysis:
1. Create a qemu qcow2 image. This is the OS complete with programs. Assume this is named: `base.qcow2`.
2. Create a snapshot qcow2 image from the `base.qcow2` using qemu-img command
   `qemu-img create -b base.qcow2 -f qcow2 snap.qcow2`
3. Inject the stuff to analyze using guestfish (http://libguestfs.org/) to `snap.qcow2`. This allows for base.qcow2 to be unchanged.
4. Run the PANDA recording in `snap.qcow2`. After the recording is finished, `snap.qcow2` can be deleted, and `base.qcow2` will stay unchanged.

The main purpose of creating hard disk snapshot using qemu-img is to reduce space usage, 
especially when the analysis is done locally in laptop / local PC.
Rather than copying the `base.qcow2` for all recording process, only one `base.qcow2` is needed here, and 
only `snap.qcow2` is copied around. `snap.qcow2` is much more space friendly (only ~50MB)

Another benefit is to enforce uniform initial conditions for all PANDA recordings.


Short plugin description
------------------------

dyevdtsizeofimg: checking whether application writes to Size Of Image  
dyevdtnopseq: checking whether application executes N-nop instructions  
exectrace: produce execution trace of guest code within specified address space range  
bufmon: bufmon port from PANDA1 to PANDA2. bufmon2 is the old version of this plugin.  


