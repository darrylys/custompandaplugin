
#include "osi_process.h"

void dump_OsiModule(FILE *file, const OsiModule &in) {
    fprintf(file, "OsiModule {\n");
    
    fprintf(file, "\toffset: 0x%016lx\n", (uint64_t)in.offset);
    fprintf(file, "\tbase: 0x%016lx\n", (uint64_t)in.base);
    fprintf(file, "\tentry point: 0x%016lx\n", (uint64_t)in.ep);
    fprintf(file, "\timage size: %u\n", in.size);
    fprintf(file, "\tfull dll name: '%s'\n", in.full_dll_name.c_str());
    fprintf(file, "\tbase dll name: '%s'\n", in.base_dll_name.c_str());
    
    fprintf(file, "}\n");
}

void dump_OsiProcess(FILE * file, const OsiProcess &in) {
    fprintf(file, "OsiProcess {\n");
    
    fprintf(file, "\teproc: 0x%016lx\n", (uint64_t)in.eproc);
    fprintf(file, "\timageName: '%s'\n", in.imageName.c_str());
    fprintf(file, "\tasid: 0x%016lx\n", (uint64_t)in.asid);
    fprintf(file, "\tpid: 0x%x (%u)\n", in.pid, in.pid);
    fprintf(file, "\tppid: 0x%x (%u)\n", in.ppid, in.ppid);
    
    fprintf(file, "}\n");
}
