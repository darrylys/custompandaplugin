
#include "osi_process.h"
#include "logger.h"

void dump_OsiModule(const OsiModule &in) {
    MYINFO( "%s", "OsiModule {");
    
    MYINFO( "\toffset: 0x%016lx", (uint64_t)in.offset);
    MYINFO( "\tbase: 0x%016lx", (uint64_t)in.base);
    MYINFO( "\tentry point: 0x%016lx", (uint64_t)in.ep);
    MYINFO( "\timage size: %u", in.size);
    MYINFO( "\tfull dll name: '%s'", in.full_dll_name.c_str());
    MYINFO( "\tbase dll name: '%s'", in.base_dll_name.c_str());
    
    MYINFO( "%s", "}");
}

void dump_OsiProcess(const OsiProcess &in) {
    MYINFO( "%s", "OsiProcess {");
    
    MYINFO( "\teproc: 0x%016lx", (uint64_t)in.eproc);
    MYINFO( "\timageName: '%s'", in.imageName.c_str());
    MYINFO( "\tasid: 0x%016lx", (uint64_t)in.asid);
    MYINFO( "\tpid: 0x%x (%u)", in.pid, in.pid);
    MYINFO( "\tppid: 0x%x (%u)", in.ppid, in.ppid);
    
    MYINFO( "%s", "}");
}
