#include <stdio.h>
#include <stdint.h>

#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plugin_plugin.h"
#include "panda/rr/rr_log_all.h"

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#ifdef ECLIPSE
typedef uint32_t target_ulong;
typedef int32_t target_long;
#endif

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

#define G_PLUGIN_NAME "hdtransfertest"

target_ulong gTargetAsid;
FILE* gOutput;

bool isPrintableAscii(uint32_t data) {
    return data >= 0x20 && data <= 0x7e;
}

std::string getAscii(const uint8_t* buf, uint32_t len) {
    std::stringstream ss;

    for (uint32_t i=0; i<len; ++i) {
        if (isPrintableAscii(buf[i])) {
            ss << (char)buf[i];
        } else {
            ss << ".";
        }
    }

    return ss.str();
}

std::string getBytesStr(const uint8_t* buf, uint32_t len) {
    std::stringstream ss;

    for (uint32_t i=0; i<len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (uint32_t)buf[i] << " ";
    }

    return ss.str();
}

int replay_hd_transfer(CPUState *env, uint32_t type, uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes) {
    target_ulong currentAsid = panda_current_asid(env);
    if (currentAsid != gTargetAsid) {
        return 0;
    }

    const char * typeStr;
    switch (type) {
    case HD_TRANSFER_HD_TO_IOB:
        typeStr = "HD2IOB";
        break;

    case HD_TRANSFER_HD_TO_RAM:
        typeStr = "HD2RAM";
        break;

    case HD_TRANSFER_IOB_TO_HD:
        typeStr = "IOB2HD";
        break;

    case HD_TRANSFER_IOB_TO_PORT:
        typeStr = "IOB2PORT";
        break;

    case HD_TRANSFER_PORT_TO_IOB:
        typeStr = "PORT2IOB";
        break;

    case HD_TRANSFER_RAM_TO_HD:
        typeStr = "RAM2HD";
        break;

    default:
        typeStr = "?";
        break;

    }

    RR_prog_point pp = rr_prog_point();

    std::vector<uint8_t> vBuf(num_bytes);
    if (MEMTX_OK == panda_physical_memory_rw(src_addr, &vBuf[0], num_bytes, false)) {
        // ok
        std::string bytesAscii = getBytesStr(&vBuf[0], num_bytes);
        std::string charAscii = getAscii(&vBuf[0], num_bytes);
        fprintf(gOutput, "%lu %s %16lx -> %16lx %s (%s)\n",
                pp.guest_instr_count, typeStr, src_addr, dest_addr, bytesAscii.c_str(), charAscii.c_str());

    } else {
        // error
        fprintf(gOutput, "[ERROR] %lu %s %016lx -> %16lx failed read\n",
                pp.guest_instr_count, typeStr, src_addr, dest_addr);

    }

    return 0;
}

bool init_plugin(void* self) {
    panda_enable_precise_pc();
    panda_enable_memcb();

    panda_arg_list *args = panda_get_args(G_PLUGIN_NAME);
    const char * str_asid = panda_parse_string(args, "asid", NULL);
    if (!str_asid) {
        fprintf(stderr, "unable to proceed, give asid for monitoring using asid parameter! "
                "asid is hex string without 0x\n");
        return false;
    }
    uint64_t asid;
    ::sscanf(str_asid, "%lx", &asid);
    gTargetAsid = (target_ulong) asid;
    fprintf(stderr, "watching asid: %08x\n", (uint32_t)gTargetAsid);

    gOutput = fopen(G_PLUGIN_NAME ".log", "w");
    if (gOutput == NULL) {
        fprintf(stderr, "Failed opening file " G_PLUGIN_NAME ".log" "for writing\n");
        return false;
    }

    panda_cb pcb;
    pcb.replay_hd_transfer = replay_hd_transfer;
    panda_register_callback(self, PANDA_CB_REPLAY_HD_TRANSFER, pcb);

    panda_free_args(args);

    return true;
}

void uninit_plugin(void * self) {
    if (gOutput) {
        fflush(gOutput);
        fclose(gOutput);
    }
}
