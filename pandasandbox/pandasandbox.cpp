#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plugin_plugin.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include <functional>
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "asidstory/asidstory.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"
#include "win7x86intro/win7x86intro_ext.h"

// old panda
//#include "syscalls2/gen_syscalls_ext_typedefs.h"
#include "syscalls2/generated/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

#include "Tracer.h"
#include <cstdio>
#include <cstdint>
#include <assert.h>

#define G_PLUGIN_NAME "pandasandbox"

class PandaTrcEnv : public tracer::ITrcEnv {
public:
	PandaTrcEnv(){}
	~PandaTrcEnv(){}
	bool get_mixin(tracer::ENV_MIXIN& out, void* param) {
		/*
		if (param == NULL) {
			return false;
		}
		
		CPUState* cpu = reinterpret_cast<CPUState*>(param);
		out.asid = panda_current_asid(cpu);
		out.pid = ::get_pid(cpu);
		out.tid = ::get_tid(cpu);
		
		RR_prog_point pp = rr_prog_point();
		out.instrcnt = pp.guest_instr_count;
		out.pc = panda_current_pc(cpu);
		
		return true;
		*/
		return false;
	}
	
};

PandaTrcEnv gPandaTrcEnv;
bool gCapstoneOpened;
csh gCapstoneHandle;
uint32_t gInsnCounter = 0;

extern "C" 
{
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

bool pcbBeforeInsnTranslate_MarkNewInsn(CPUState *env, target_ulong pc) {
	#if defined(TARGET_I386)
	return true;
	#endif
	return false;
}

int pcbBeforeInsnExec(CPUState *env, target_ulong pc) {
	#if defined(TARGET_I386)
	
	target_ulong current_asid = panda_current_asid(env);
	//target_ulong jmp_addr = 0x9a8610;
	RR_prog_point pp = rr_prog_point();
	
	if (current_asid == 0x2135b000) {
		if (pp.guest_instr_count >= 499158280) {
			
			tracer::TrcTrace(env, TRC_BIT_INFO, "pc = %08x", pc);
			
			target_ulong current_pc = panda_current_pc(env);
			tracer::TrcTrace(env, TRC_BIT_INFO, "panda_current_pc = %08x", current_pc);
			
			CPUArchState* arch = reinterpret_cast < CPUArchState* > (env->env_ptr);
			target_ulong eip = arch->eip;
			tracer::TrcTrace(env, TRC_BIT_INFO, "arch->eip = %08x", eip);
			
			gInsnCounter++;
			
			if (gInsnCounter >= 20) {
				assert(false);
			}
		}
	}
	
	#endif
	return 0;
}

bool init_plugin(void * self) {
	#if defined(TARGET_I386)
	
	tracer::TrcInit(G_PLUGIN_NAME ".debug.log", 
			TRC_BIT_DEBUG | TRC_BIT_INFO | TRC_BIT_WARN | TRC_BIT_ERROR, 
			&gPandaTrcEnv);
	
	panda_enable_memcb();
    panda_enable_precise_pc();
	
	gCapstoneOpened = false;
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &gCapstoneHandle) != CS_ERR_OK) {
#elif defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &gCapstoneHandle) != CS_ERR_OK) {
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_32, &gCapstoneHandle) != CS_ERR_OK) {
#else
    if (true) {
#endif
        fprintf(stderr, "[error] Unable to load capstone library\n");
        return false;
    }
	// no need for details switch for now.
    //cs_option(gCapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
    //cs_option(gCapstoneHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
    gCapstoneOpened = true;
	
	panda_cb pcb;

	pcb.insn_translate = pcbBeforeInsnTranslate_MarkNewInsn;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = pcbBeforeInsnExec;
	panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
	
	return true;
	
	#endif
	
	return false;
}

void uninit_plugin(void * self) {
	#if defined(TARGET_I386)
	
	if (gCapstoneOpened) {
        cs_close(&gCapstoneHandle);
    }
	
	tracer::TrcClose();
	
	#endif
}

