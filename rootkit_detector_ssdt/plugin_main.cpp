
//#define NETBEANS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "winhelper.h"

#ifdef NETBEANS
#include "exec/cpu-all.h"
#endif

#include "winpehdr.h"

#ifdef NETBEANS
typedef uint64_t target_ulong;
#endif

#define N__PLUGIN_NAME__ "rootkit_detector_ssdt"

FILE * g_debug_log;

namespace winpe {
    class WinPEPanda : public WinPE {
    public:
        WinPEPanda(CPUState *env, peaddr_t pe_base)
        : WinPE(pe_base, g_debug_log), m_env(env)
        {
#ifdef WINPE_DEBUG
            fprintf(g_debug_log, "WinPEPanda()\n");
#endif
        }
        
        ~WinPEPanda() {
#ifdef WINPE_DEBUG
            fprintf(g_debug_log, "~WinPEPanda()\n");
#endif           
        }
        
    protected:
        virtual int read_mem(peaddr_t src, uint8_t *out, int size) {
            if (-1 == panda_virtual_memory_read(m_env, src, out, size)) {
                return 0;
            }
            return size;
        }
        
    private:
        CPUState * m_env;
    };
}

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    
    int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, 
            target_ulong newval);
}



#define PTR panda::win::ptr_t

// this returns 0x804d7000 as well
// according to uninformed.org in finding ntoskrnl.exe base, this result matches
// with Windows XP SP2 / SP3. This seems promising!
// next step is to create a Windows PE header parser to find the Export table!
PTR find_ntoskrnl_base_addr_via_idlethread(CPUState *env) {
#if defined(TARGET_I386)
    
    PTR kpcr = panda::win::get_kpcr(env);
    PTR idle_addr;
    if (-1 == panda_virtual_memory_read(env, kpcr + KPCR_IDLETHRAD_OFF, 
            (uint8_t*)&idle_addr, sizeof(idle_addr))) {
        return 0;
    }
    
    // find ntoskrnl base addr by looping and find MZ signature
    PTR start = (PTR)(idle_addr & 0xFFFFF000);
    
    // in volatility, the search is 5 MB. Since disk block size is 512 byte 
    // and memory block is 4KB
    // we try to multiply the search by 8.
    for (unsigned int i=0; i<40*1024*1024; i += 0x1000) {
        uint16_t word;
        if (-1 == panda_virtual_memory_read(env, start - i, (uint8_t*)&word, 
                sizeof(word))) {
            
            continue;
        }
        
        // MZ signature ('ZM' for Little Endian)
        if (word == 0x5a4d) {
            return start - i;
        }
    }
    
    return 0;
    
#elif defined (TARGET_X86_64)
    return 0;
    
#elif defined (TARGET_ARM)
    return 0;
	
#else
#error "Unsupported Architecture!"
#endif
    
    return 0;
}

int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, 
        target_ulong newval) {
    
//    fprintf(g_debug_log, "\n============================== CHECK SSDT HOOKS ===================================\n");
    
//    if (g_KiServiceTable == 0) {
        
    // obtain the ntoskrnl.exe base addr
    PTR nt_base = find_ntoskrnl_base_addr_via_idlethread(env);
    winpe::WinPEPanda oEP(env, nt_base);
    
//    fprintf(g_debug_log, "ntoskrnl.exe (temp) [0x%08x, 0x%08x]\n", oEP.get_low_addr(), oEP.get_high_addr());
    
    PTR KeServiceDescriptorTable = oEP.get_export_func(
            "KeServiceDescriptorTable");
//    fprintf(g_debug_log, "KeServiceDescriptorTable at 0x%016lx\n", (uint64_t)KeServiceDescriptorTable);
    
    PTR KiServiceTable;
    
    PTR service_table_via_kthread = panda::win::get_tcb_service_table(env);
    
    if (-1 == panda_virtual_memory_read(env, KeServiceDescriptorTable + 
            SSDT_SERVICE_TABLE_OFF, (uint8_t*)&KiServiceTable, 
            sizeof(KiServiceTable))) {
        
        return 0;
    }
    
    uint32_t KiServiceLimit;
    if (-1 == panda_virtual_memory_read(env, KeServiceDescriptorTable + 
            SSDT_SERVICE_LIMIT_OFF, (uint8_t*)&KiServiceLimit, 
            sizeof(KiServiceLimit))) {
        
        return 0;
    }
    
    
    // service_table_via_kthread is KeServiceDescriptorTable.
    // 
//    fprintf(g_debug_log, 
//            "KeServiceDescriptorTable: 0x%016x, "
//            "KiServiceTable: 0x%016x, "
//            "service_table_via_kthread: 0x%016x, "
//            "== %d\n",
//            KeServiceDescriptorTable,
//            KiServiceTable, 
//            service_table_via_kthread, 
//            KiServiceTable == service_table_via_kthread);
    
    PTR KeServiceDescriptorTableShadow = KeServiceDescriptorTable + 
            SSDT_SERVICE_TBL_SHADOW_FROM_TBL_OFF;
    
    if (service_table_via_kthread != KeServiceDescriptorTable &&
            service_table_via_kthread != KeServiceDescriptorTableShadow) {
        
        fprintf(g_debug_log, "SSDT from KTHREAD is moved to 0x%016x\n", 
                service_table_via_kthread);
        
    }
    
    // loop the KiServiceTable, find the pointer outside the ntoskrnl.exe address range above.
//    fprintf(g_debug_log, "Check SSDT hooks\n");
    PTR ki_ssdt_syscall_addr;
    for (uint32_t i=0; i<KiServiceLimit; ++i) {
        
        if (-1 == panda_virtual_memory_read(env, KiServiceTable + 
                (i*sizeof(PTR)), (uint8_t*)&ki_ssdt_syscall_addr, 
                sizeof(ki_ssdt_syscall_addr))) {
            
            return 0;
        }
        
//        fprintf(g_debug_log, "\tENTRY: 0x%x(%u) --> 0x%016lx\n", i, i, 
//        (uint64_t)ki_ssdt_syscall_addr);
        
        // check if the func is outside ntoskrnl.exe
        if (ki_ssdt_syscall_addr < oEP.get_low_addr() ||
                ki_ssdt_syscall_addr > oEP.get_high_addr()) {
            // found!
            
            // we should add syscall names here!!
            fprintf(g_debug_log, "0x%x (%u) --> 0x%016lx\n", i, i, 
                    (uint64_t)ki_ssdt_syscall_addr);
            
        }
        
    }
//    fprintf(g_debug_log, "Check SSDT end\n");
    
//    }
    
    return 0;
}

bool init_plugin(void *self) {
    
    g_debug_log = NULL;
    //g_KiServiceTable = 0;
    
#if defined(TARGET_I386)
    
    g_debug_log = fopen("rootkit_detector.ssdt.log", "w");
    
    if (g_debug_log) {
        fprintf(g_debug_log, "Initializing plugin '%s'\n", N__PLUGIN_NAME__);
    } else {
        return false;
    }
    
    panda_enable_precise_pc();
    panda_enable_memcb();

    //printf("g_panda_env=0x%p\n", g_panda_env);
    //printf("g_loop_detector_engine=0x%p\n", g_loop_detector_engine);

    panda_cb pcb;

    pcb.asid_changed = on_after_asid_changed_cb;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    
    return true;
    
#endif
    
    return false;
    
}

void uninit_plugin(void *self) {
    
    // dump all information in loop here
    // maybe later I'll add the interface function
    
    if (g_debug_log) {
        fprintf(g_debug_log, "uninit_plugin\n");
    }
    
    if (g_debug_log) {
        fclose(g_debug_log);
    }
}
