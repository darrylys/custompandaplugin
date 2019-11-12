#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plugin_plugin.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include <functional> // required for callstack_instr.h prog_point if __cplusplus is defined
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"
#include "win7x86intro/win7x86intro_ext.h"

// old panda
//#include "syscalls2/gen_syscalls_ext_typedefs.h"
#include "syscalls2/generated/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "dyremoteprocwrite/dyremoteprocwrite.h"
#include "dywin7x86sp1apilogger/dywin7x86sp1apilogger.h"
#include "dywin7x86sp1apilogger/dywin7x86sp1apilogger_ext.h"

#include "dbgdefs.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <set>
#include "proc_util.h"
#include "AnalysisEngine.h"
#include "win7objecttypes.h"
#include "Tracer.h"
#include "miscfunc.h"

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

#define G_PLUGIN_NAME "dypandasok"
#define CSV_SEPARATOR ('|')

AnalysisEngine* gPtrEngine;
FILE * gOutputFile;

class PandaTrcEnv : public tracer::ITrcEnv {
public:
	PandaTrcEnv(){}
	~PandaTrcEnv(){}
	bool get_mixin(tracer::ENV_MIXIN& out, void* param) {
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
	}
	
};
PandaTrcEnv g_trc_env;

typedef struct _ProcFilter {
	uint32_t pid;
	uint64_t asid;
} ProcFilter;
// list of processes to filter. Currently, only support one process
// key: pid of process, value: process filter criteria.
std::map < uint32_t, ProcFilter > gProcFilter;
std::map < uint64_t, uint32_t > gAsid2Pid;

// pair of < asid, pc >
// no need for thread id because all threads share same memory space!!
typedef std::pair < target_ulong, target_ulong > InsnKey;
std::map < InsnKey, bool > gIsNewInsn;
InsnKey createInsnKey(target_ulong asid, target_ulong pc) {
	return std::make_pair(asid, pc);
}

std::map < InsnKey, bool > gIsValidInsn;

// records the last insn head of Basic Block executed 
std::map < InsnKey, target_ulong > gLastInsnBBHeadExec;
InsnKey createLastInsnKey(target_ulong asid, target_ulong tid) {
	return createInsnKey(asid, tid);
}

// flag whether a call is executed previously per thread.
// map = (asid, tid) --> bool
/*
std::map < std::pair < target_ptr_t, target_pid_t >, bool > gThreadCall;

bool is_call_executed(target_ptr_t asid, target_ptr_t tid) {
	auto key = std::make_pair(asid, tid);
	auto it = gThreadCall.find(key);
	
	if (it == gThreadCall.end()) {
		return false;
	} else {
		return it->second;
	}
}

void set_call_executed(target_ptr_t asid, target_ptr_t tid, bool executed) {
	auto key = std::make_pair(asid, tid);
	gThreadCall[key] = executed;
}
*/
target_ulong gStartAnalysisAddr;
target_ulong gEndAnalysisAddr;

csh gCapstoneHandle;
bool gCapstoneOpened;
bool gOnlyRecordAPIsFromModule;

#define W7X86SP1_TIB_STACK_LIMIT_OFF 		(0x8)
#define W7X86SP1_TIB_STACK_BASE_OFF			(0x4)
#define W7X86SP1_USER_TEB_PPEB_OFF			(0x30)
#define W7X86SP1_USER_PEB_IMAGEBASEADDR_OFF	(0x8)

extern "C" 
{
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

class PandaEnv : public IEnvironment {
public:
	PandaEnv() {
		
	}
	
	~PandaEnv() {
		
	}
	
	ENV_RET read(void* env, addr_t addr, uint8_t* outBuf, int outLen) {
		#if defined(TARGET_I386)
		CPUState* cpu = reinterpret_cast < CPUState* > (env);
		if (-1 == panda_virtual_memory_read(cpu, (target_ulong)addr, outBuf, outLen)) {
			return ENV_RET_S_ERR;
		}
		return ENV_RET_S_OK;
		#endif
		return ENV_RET_S_ERR;
	}
	
	uint64_t read_stack_base(void* env) {
		/*#if defined(TARGET_I386)
		CPUState* cpu = reinterpret_cast < CPUState* > (env);
		CPUArchState* arch = reinterpret_cast < CPUArchState* > (cpu->env_ptr);
		return arch->regs[R_EBP];
		#endif
		fprintf(stderr, "Does not support other than x86\n");
		assert(false);*/
		uint64_t x = this->_read_fs_with_off(reinterpret_cast<CPUState*>(env), W7X86SP1_TIB_STACK_BASE_OFF);
		assert(x > 0);
		return x;
	}
	
	uint64_t read_stack_pointer(void* env) {
		#if defined(TARGET_I386)
		CPUState* cpu = reinterpret_cast < CPUState* > (env);
		CPUArchState* arch = reinterpret_cast < CPUArchState* > (cpu->env_ptr);
		return arch->regs[R_ESP];
		#endif
		fprintf(stderr, "Does not support other than x86\n");
		assert(false);
	}
	
	uint64_t read_stack_limit(void* env) {
		uint64_t x = this->_read_fs_with_off(reinterpret_cast<CPUState*>(env), W7X86SP1_TIB_STACK_LIMIT_OFF);
		assert(x > 0);
		return x;
	}
	
	uint64_t read_image_base(void * env) {
		#if defined(TARGET_I386)
		
		CPUState* cpu = reinterpret_cast < CPUState* > (env);
		
		// in kernel, fs register points to KPCR struct, which does not have PEB.
		// only in user mode, fs register points to TEB, which contains pointer to PEB in offset 0x30
		assert(!panda_in_kernel(cpu)); 
		
		CPUArchState* arch = reinterpret_cast < CPUArchState* > (cpu->env_ptr);
		target_ulong fs = arch->segs[R_FS].base;
		target_ulong ppeb = fs + W7X86SP1_USER_TEB_PPEB_OFF; // address of PPEB entry in TEB
		target_ulong peb = 0;
		assert(-1 != panda_virtual_memory_read(cpu,
			ppeb, (uint8_t*)(&peb), sizeof(peb)));
		assert(peb > 0);									 // address of PEB
		target_ulong image_base = 0;
		assert(-1 != panda_virtual_memory_read(cpu, 
			peb + W7X86SP1_USER_PEB_IMAGEBASEADDR_OFF, 
			(uint8_t*)(&image_base), sizeof(image_base)));
		assert(image_base > 0);
		return image_base;
		#endif
		assert(false);
	}
	
	uint64_t read_guest_insnctr(void* env) {
		RR_prog_point pp = rr_prog_point();
		return pp.guest_instr_count;
	}
	
	uint32_t get_functions(addr_t fn_out[], uint32_t n_fn, void* env) {
		
		assert(n_fn > 0);
		
		uint32_t nfunc = 0;
		std::vector < target_ulong > vbuf(n_fn);
		nfunc = ::get_functions(&vbuf[0], (uint32_t)n_fn, 
				reinterpret_cast < CPUState* > (env));
		
		for (uint32_t i = 0; i < nfunc; ++i) {
			fn_out[i] = vbuf[i];
		}
		return nfunc;
		
	}
	
	uint32_t get_callers(addr_t cl_out[], uint32_t n_cl, void* env) {
		
		assert(n_cl > 0);
		
		uint32_t ncaller = 0;
		std::vector < target_ulong > vbuf(n_cl);
		ncaller = ::get_callers(&vbuf[0], (uint32_t)n_cl, 
				reinterpret_cast < CPUState* > (env));
		
		for (uint32_t i = 0; i < ncaller; ++i) {
			cl_out[i] = vbuf[i];
		}
		return ncaller;
		
	}
	
	bool get_program_point(void* env, PROGRAM_POINT& out) {
		prog_point pp = {0};
		::get_prog_point(reinterpret_cast < CPUState* > (env), &pp);
		
		out.caller = pp.caller;
		//out.cr3 = pp.cr3;
		out.cr3 = pp.sidFirst;
		out.pc = pp.pc;
		
		return true;
	}
	
private:
	uint64_t _read_fs_with_off(CPUState* cpu, int off) {
		#if defined(TARGET_I386)
		CPUArchState* arch = reinterpret_cast < CPUArchState* > (cpu->env_ptr);
		target_ulong fs = arch->segs[R_FS].base;
		target_ulong tmp = 0;
		if (-1 == panda_virtual_memory_read(cpu, fs + off, 
		(uint8_t*) (&tmp), sizeof (tmp))) {
			return 0;
		} else {
			return tmp;
		}
		#endif
		assert(false);
	}
};

PandaEnv gPandaEnv;

target_ulong vmax(target_ulong a, target_ulong b) {
    return a > b ? a : b;
}

/**
 * @brief Checks whether current PID is targeted for analysis
 * @param env
 * @return 
 */
bool isRunningAnalysisWithPid(CPUState* env) {
	uint32_t currentPid = (uint32_t)get_pid(env);
	return gPtrEngine->isAnalyzePid(currentPid);
	//return gProcFilter.find(currentPid) != gProcFilter.end();
}

/**
 * @brief Checks whether given address is within analysis address range
 * addr >= (uint64_t)gStartAnalysisAddr && addr < (uint64_t)gEndAnalysisAddr;
 * @param addr
 * @return 
 */
bool isAddrInAnalysisSpace(uint64_t addr) {
	return gPtrEngine->isInAnalysisSpace(addr);
	//return addr >= (uint64_t)gStartAnalysisAddr && 
	//	   addr < (uint64_t)gEndAnalysisAddr;
}

/**
 * @brief Checks whether current Asid is targeted for analysis
 * @param env
 * @return 
 */
bool isRunningAnalysisWithAsid(CPUState* env) {
	target_ulong currentAsid = panda_current_asid(env);
	return gPtrEngine->isAnalyzeAsid(currentAsid);
	//auto it = gAsid2Pid.find(currentAsid);
	//return it != gAsid2Pid.end();
}

/**
 * @brief Checks whether supplied program counter is within analysis
 * space and the current asid is the target asid to analyze.
 * @param env
 * @param pc
 * @return 
 */
bool isRunningAnalysisInCurrentPC(CPUState* env, uint64_t pc) {
	if (!isRunningAnalysisWithAsid(env)) {
		return false;
	}
	
	if (!isAddrInAnalysisSpace(pc)) {
		return false;
	}
    
    return true;
}

/**
 * @see isRunningAnalysisInCurrentPC
 * @brief just calls isRunningAnalysisInCurrentPC
 * @param env
 * @param pc
 * @return 
 */
bool isRunningAnalysisHere(CPUState* env, uint64_t pc) {
    return isRunningAnalysisInCurrentPC(env, pc);
}

/**
 * @brief checks whether addr is in user address range (addr < 0x80000000LL)
 * @param addr
 * @return 
 */
bool isAddrInUserSpace(uint64_t addr) {
	return addr < 0x80000000LL; // kernel.
}

/**
 * @brief Checks whether analysis is run. This checks for asid, pid and whether
 * the executing address is within user space range (default = 0 to 0x0fffffff)
 * 
 * @param env
 * @param pc
 * @return 
 */
bool isRunningExecutionAnalysis(CPUState* env, uint64_t pc) {
	return isRunningAnalysisWithAsid(env) && 
			isRunningAnalysisWithPid(env) &&
			isAddrInUserSpace(pc);
}

/**
 * @brief This simply marks the "to-be" translated insn at pc to be analyzed.
 * They will be analyzed in beforeInsncallback. This is because, it is possible that
 * the page containing address pc has not been added to TB cache, causing error when
 * trying to read them using panda_virt_mem_read. Hopefully, the page containing pc
 * is already accessible before execution.
 * 
 * @param env
 * @param pc
 * @return 
 */
bool pcbBeforeInsnTranslate_MarkNewInsn(CPUState *env, target_ulong pc) 
{
	#if defined(TARGET_I386)
	if (!(isRunningAnalysisWithAsid(env) && isRunningAnalysisWithPid(env) && isAddrInAnalysisSpace(pc))) {
		return false;
	}
	
	target_ulong asid = panda_current_asid(env);
	InsnKey key = createInsnKey(asid, pc);
	gIsNewInsn[key] = true;
	return true;
	
	#endif
	return false;
}

/**
 * Limits the number of instructions where before-exec callback is generated
 * since this process is fairly expensive
 * 
 * @return true if the instruction before-exec callback will be generated, 
 * false otherwise
 */ 
bool pcbBeforeInsnTranslate(CPUState *env, target_ulong pc)
{
#if defined(TARGET_I386)

	if (!(isRunningAnalysisWithAsid(env) && isRunningAnalysisWithPid(env) && isAddrInAnalysisSpace(pc))) {
		return false;
	}
	
	tracer::TrcTrace(env, TRC_BIT_DEBUG, ">> pcbBeforeInsnTranslate(%lx)", (uint64_t)pc);

    int insnSize = 0;
    uint8_t buf[32];
    if (-1 == panda_virtual_memory_read(env, pc, buf, sizeof(buf))) {
		tracer::TrcTrace(env, TRC_BIT_WARN, "failed to read "
				"code at address 0x%lx\n", (uint64_t)pc);

    } else {
        // just disassemble 1 instruction.
        cs_insn * insn;
        size_t count = cs_disasm(gCapstoneHandle, buf, sizeof(buf), pc, 1, &insn);
        if (count > 0) {
            insnSize = insn[0].size;
            cs_free(insn, count);
        } else {
			tracer::TrcTrace(env, TRC_BIT_WARN, "failed to disas"
					"semble code at address 0x%lx\n", (uint64_t)pc);
            
        }
    }
	
	// for some reason, sometimes, the given pc is simply wrong,
	// example in exeshield 3.7. After some instructions, it returns to
	// the correct execution.
	InsnKey valid_key = createInsnKey(panda_current_asid(env), pc);
	if (insnSize == 0) {
		gIsValidInsn[valid_key] = false;
		return false;
	}
	
	gIsValidInsn[valid_key] = true;
	
    //assert(insnSize > 0);
	
	EXEC_ENV_PARAM env_param;
	env_param.asid = panda_current_asid(env);
	env_param.pid = (proccess_id_t)get_pid(env);
	env_param.tid = (thread_id_t)get_tid(env);
	
	INS_PARAM ins_param;
	ins_param.addr = (addr_t)pc;
	ins_param.size = (uint32_t)insnSize;
	ins_param.buf = buf;
	
	int ret = gPtrEngine->onBeforeInsnTranslate(env_param, ins_param, env);
	tracer::TrcTrace(env, TRC_BIT_DEBUG, "<< pcbBeforeInsnTranslate(): returns %d", ret);
	
    return ret > 0;
#endif
    return false;
}

void hard_check_valid_insn(CPUState* env, target_ulong asid, target_ulong pc) {
	InsnKey valid_key = createInsnKey(asid, pc);
	auto vkit = gIsValidInsn.find(valid_key);
	
	if (vkit == gIsValidInsn.end()) {
		tracer::TrcTrace(env, TRC_BIT_ERROR, "Error, vkit == gIsValidInsn.end()");
		assert(false);
	}
	
	if (!vkit->second) {
		tracer::TrcTrace(env, TRC_BIT_ERROR, "Error, vkit->second is false!");
		assert(false);
	}
}

bool soft_check_valid_insn(CPUState* env, target_ulong asid, target_ulong pc) {
	InsnKey valid_key = createInsnKey(asid, pc);
	auto vkit = gIsValidInsn.find(valid_key);
	
	return vkit != gIsValidInsn.end() && vkit->second;
}

/**
 * This function is to find the transitions, namely, the previous instruction
 * address.
 */ 
int pcbBeforeInsnExec(CPUState *env, target_ulong pc)
{
#if defined(TARGET_I386)
	
	// dunno why, but this somehow fixed the segfault issue.
	if (!(isRunningAnalysisWithAsid(env) && isRunningAnalysisWithPid(env) && isAddrInAnalysisSpace(pc))) {
		return 0;
	}
	
	// use hard check here because if translate returns false, it shouldn't invoke this function at all.
	hard_check_valid_insn(env, panda_current_asid(env), pc);
	
	tracer::TrcTrace(env, TRC_BIT_DEBUG, ">> pcbBeforeInsnExec(%lx)", (uint64_t)pc);
	
	EXEC_ENV_PARAM env_param;
	env_param.asid = panda_current_asid(env);
	env_param.pid = (proccess_id_t)get_pid(env);
	env_param.tid = (thread_id_t)get_tid(env);
	
	INS_PARAM ins_param;
	ins_param.addr = (addr_t)pc;
	
	// these placeholders will be filled with correct ones in onBeforeInsnExec, PROVIDED
	// the onBeforeInsnTranslate is correctly executed beforehand!
	ins_param.size = 0;
	ins_param.buf = NULL;
	
	gPtrEngine->onBeforeInsnExec(env_param, ins_param, env);
	
	tracer::TrcTrace(env, TRC_BIT_DEBUG, "<< pcbBeforeInsnExec(%lx)", (uint64_t)pc);
	
	
#endif
    return 0;
}

bool pcbAfterInsnTranslate(CPUState *env, target_ulong pc)
{
//    return pcbBeforeInsnTranslate(env, pc);
	return false;
}

int pcbAfterInsnExec(CPUState *env, target_ulong pc)
{
    //return pcbBeforeInsnExec(env, pc);
	return 0;
}

int pcbOnVirtMemWrite(
    CPUState *env, target_ulong pc, 
    target_ulong addr, target_ulong size, void *buf) 
{
#if defined(TARGET_I386)
	
	// allow pc from any source, from kernel is fine too,
	// as long as the current Asid, PID are within analysis targets and write address
	// is within analysis address range
	// after contemplation, just force analysis only on assigned addresses
	if (!(isRunningAnalysisWithAsid(env) && 	// only allow configured asids
	isRunningAnalysisWithPid(env) && 			// only allow configured pids
	isAddrInAnalysisSpace(addr) && 				// check target write address
	isAddrInAnalysisSpace(pc))) {				// check address of running instruction
		return 0;
	}
	
	if (!soft_check_valid_insn(env, panda_current_asid(env), pc)) {
		tracer::TrcTrace(env, TRC_BIT_WARN, "pcbOnVirtMemWrite:: invalid insn (pc=%08lx) from qemu", (uint64_t)pc);
		return 0;
	}
	
	tracer::TrcTrace(env, TRC_BIT_DEBUG, ">> pcbOnVirtMemWrite(pc=%lx, addr=%lx, size=%u, buf=%016lx)",
			(uint64_t)pc, (uint64_t)addr, (uint32_t)size, (uint64_t)(*(reinterpret_cast<uint64_t*>(buf))));
	
	EXEC_ENV_PARAM env_param;
	env_param.asid = panda_current_asid(env);
	env_param.pid = (proccess_id_t)get_pid(env);
	env_param.tid = (thread_id_t)get_tid(env);
	
	INS_PARAM ins_param;
	ins_param.addr = (addr_t)pc;
	ins_param.size = 0;
	ins_param.buf = NULL;
	
	WRITE_PARAM write_param;
	write_param.addr = addr;
	write_param.buf = reinterpret_cast < uint8_t* > (buf);
	write_param.size = size;
	
	gPtrEngine->onBeforeWriteVirtAddr(env_param.asid, env_param, ins_param, write_param, env);
	
	tracer::TrcTrace(env, TRC_BIT_DEBUG, "<< pcbOnVirtMemWrite(pc=%lx, addr=%lx, size=%u)",
			(uint64_t)pc, (uint64_t)addr, (uint32_t)size);

#endif
    return 0;
}

void on_cbNtFreeVirtualMemory_enter(CPUState *cpu, 
target_ulong pc, uint32_t ProcessHandle, uint32_t BaseAddress, 
uint32_t RegionSize, uint32_t FreeType) {
#ifdef TARGET_I386
	if (!isRunningAnalysisWithAsid(cpu)) {
		return;
	}
	if (isAddrInAnalysisSpace(BaseAddress)) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "NtFreeVirtualMemory(%08x, %08x)", ProcessHandle, BaseAddress);
		
		EXEC_ENV_PARAM env_param;
		env_param.asid = panda_current_asid(cpu);
		env_param.pid = (proccess_id_t)get_pid(cpu);
		env_param.tid = (thread_id_t)get_tid(cpu);
		
		if (ProcessHandle == ~0) {
			gPtrEngine->onRemoveHeap(env_param, BaseAddress, cpu);
			
		} else {
			// check the processhandle
			target_ulong target_pid = process_handle_to_pid(cpu, ProcessHandle);
			if (gProcFilter.find(target_pid) != gProcFilter.end()) {
				asid_t target_asid = gProcFilter.find(target_pid)->second.asid;
				gPtrEngine->onRemoveHeapRemoteProcess(env_param, target_asid, BaseAddress, cpu);
			}
			
		}
	}
#endif	
}

// this must use onReturn! BaseAddress is most likely NULL
// if on_enter, the BaseAddress is filled on return
void on_cbNtAllocateVirtualMemory_return(
CPUState *cpu, target_ulong pc, uint32_t ProcessHandle, 
uint32_t BaseAddress, uint32_t ZeroBits, uint32_t RegionSize, 
uint32_t AllocationType, uint32_t Protect) {
#ifdef TARGET_I386
	if (!isRunningAnalysisWithAsid(cpu)) {
		return;
	}
	if (isAddrInAnalysisSpace(BaseAddress)) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "NtAllocateVirtualMemory(%08x, %08x, %08x)", ProcessHandle, BaseAddress, RegionSize);
		
		EXEC_ENV_PARAM env_param;
		env_param.asid = panda_current_asid(cpu);
		env_param.pid = (proccess_id_t)get_pid(cpu);
		env_param.tid = (thread_id_t)get_tid(cpu);
		
		if (ProcessHandle == (uint32_t)(~0)) { // current process!
			gPtrEngine->onCreateHeap(env_param, BaseAddress, RegionSize, cpu);
			
		} else {
			// check the processhandle
			target_ulong target_pid = process_handle_to_pid(cpu, ProcessHandle);
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "ProcessHandle to pid returns: %u", target_pid);
			if(gProcFilter.find(target_pid) != gProcFilter.end()) {
				asid_t target_asid = gProcFilter.find(target_pid)->second.asid;
				gPtrEngine->onCreateHeapRemoteProcess(env_param, target_asid,
					BaseAddress, RegionSize, cpu);
			}
			
		}
	}
#endif
}
void on_remote_write_ex_cb(REMOTE_WRITE* p_rmparam) {
	#ifdef TARGET_I386
	CPUState* cpu = reinterpret_cast<CPUState*>(p_rmparam->cpu);
	
	if (!isRunningAnalysisWithAsid(cpu)) {
		return;
	}
	if (!isAddrInAnalysisSpace(p_rmparam->target_addr)) {
		return;
	}
	if (!(gPtrEngine->isAnalyzeAsid(p_rmparam->source_asid) && 
	gPtrEngine->isAnalyzeAsid(p_rmparam->target_asid))) {
		return;
	}
	if (!isRunningAnalysisWithAsid(cpu)) {
		return;
	}
	
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, ">> on_remote_write_ex_cb()");
	if (p_rmparam->source_asid == panda_current_asid(cpu)) {
		// current execution context
		EXEC_ENV_PARAM env_param;
		env_param.asid = panda_current_asid(cpu);
		env_param.tid = ::get_tid(cpu);
		env_param.pid = ::get_pid(cpu);
		
		WRITE_PARAM write_param;
		write_param.addr = p_rmparam->target_addr;
		write_param.size = p_rmparam->target_write_size;
		write_param.buf = p_rmparam->target_write_bytes;
		
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "==-- env: {asid = %08lx, pid = %u, tid = %u}\n", 
				env_param.asid, env_param.pid, env_param.tid);
		
		gPtrEngine->onBeforeApiMemoryWriteBulk(p_rmparam->target_asid, env_param, write_param, cpu);
		
	} else {
		assert(gAsid2Pid.find(p_rmparam->source_asid) != gAsid2Pid.end());
		
		// current execution context
		EXEC_ENV_PARAM env_param;
		env_param.asid = p_rmparam->source_asid;
		env_param.tid = p_rmparam->source_tid;
		env_param.pid = gAsid2Pid.find(p_rmparam->source_asid)->second;
		
		WRITE_PARAM write_param;
		write_param.addr = p_rmparam->target_addr;
		write_param.size = p_rmparam->target_write_size;
		write_param.buf = p_rmparam->target_write_bytes;
		
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "!=-- env: {asid = %08lx, pid = %u, tid = %u}\n", 
				env_param.asid, env_param.pid, env_param.tid);
		
		gPtrEngine->onBeforeApiMemoryWriteBulk(p_rmparam->target_asid, env_param, write_param, 
				p_rmparam->source_pc, cpu);
		
	}
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "<< on_remote_write_ex_cb()");
	
	#endif
}

/**
 * @brief callback for on_call event of callstack_instr
 * @param env
 * @param func_ret_va
 */
/*
void on_call_mark_cb(CPUState* env, target_ulong func_ret_va) {
	#if defined(TARGET_I386)
	
	// func_ret_va is the return address after the called function returns.
	// this is because this event is emitted in after basic block exec callback
	
	if (!isRunningAnalysisWithAsid(env)) {
		return;
	}
	
	if (panda_in_kernel(env)) {
		return;
	}
	
	OsiProc* p_proc = get_current_process(env);
	OsiThread* p_thread = get_current_thread(env);
	
	if (p_proc != NULL && p_thread != NULL) {
		target_ptr_t asid = p_proc->asid;
		target_pid_t tid = p_thread->tid;
		set_call_executed(asid, tid, true);
	}
	
	free_osiproc(p_proc);
	free_osithread(p_thread);
	
	#endif
}
*/
/**
 * @brief Callback for callstack instr plugin when function returns
 * @param env
 * @param func
 */
void on_ret_callstack_instr_cb(CPUState *env, target_ulong func) {
	// NOP, unused for now
}

/**
 * @brief Callback after call instruction is executed
 * @param env
 * @param func first address of the function
 */
void on_call_cb(CPUState *env, target_ulong func) {
	#if defined(TARGET_I386)
	
	if (!isRunningAnalysisWithAsid(env)) {
		return;
	}
	
	// ignore kernel.
	if (panda_in_kernel(env)) {
		return;
	}
	
	// check caller. Only interested in API calls that are called from module.
	prog_point pp = {0};
	get_prog_point(env, &pp);
	
	if (tracer::IsTrcActive(TRC_BIT_DEBUG)) {
	
		tracer::TrcTrace(env, TRC_BIT_DEBUG, "on_call_cb, pp = {caller: %016lx, cr3: %016lx, pc: %016lx}",
				//pp.caller, pp.cr3, pp.pc);
				pp.caller, pp.sidFirst, pp.pc);
		const int CALLER_SIZE = 5;
		target_ulong callers[CALLER_SIZE]; // results in same as the prev.
		::memset(callers, 0, sizeof(callers));
		
		uint32_t ncallers = ::get_callers(callers, CALLER_SIZE, env);
		tracer::TrcTrace(env, TRC_BIT_DEBUG, ">>>> callers (n=%d):", ncallers);
		for (uint32_t i=0; i<ncallers; ++i) {
			tracer::TrcTrace(env, TRC_BIT_DEBUG, " [%d]=%08lx", i, callers[i]);
		}
	
	}
	
	//target_ulong current_pc = panda_current_pc(env);
	
	EXEC_ENV_PARAM env_param;
	env_param.asid = panda_current_asid(env);
	env_param.tid = ::get_tid(env);
	env_param.pid = ::get_pid(env);
	
	// fatal bug on panda_current_sp. It seems that the developer forget the ! sign when panda_in_kernel hits!
	// Checked in latest panda (12 April 2019) and this bug has not been fixed!!
	
	// after testing, it makes more sense to use pp.pc instead of pp.caller
	// after further testing, pp.pc is sometimes unreliable, in WinUpack0.39 address 41bb44 which calls
	// OleInitialize which starts at 0x76ecefd7, somehow the pp.pc points to kernel address (0x8XXXXXXX)
	// but the caller is Okay.
	// but, caller has some issues of its own. Better make caller marking process idempotent. Only remove if
	// current execution address is in the return address of API call.
	//if (!(pp.cr3 == panda_current_asid(env) && isAddrInAnalysisSpace(pp.pc) && 
	// grab previous insn
	target_ulong lastInsnAddr = 0;
	InsnKey lastInsnKey = createLastInsnKey(env_param.asid, env_param.tid);
	auto prevInsnIt = gLastInsnBBHeadExec.find(lastInsnKey);
	bool fApiCalledFromModule = false;
	
	if (prevInsnIt != gLastInsnBBHeadExec.end()) {
		// finally, use homegrown approach instead, seems most reliable.
		lastInsnAddr = prevInsnIt->second;
		//tracer::TrcTrace(env, TRC_BIT_DEBUG, "lastInsnAddr=%08lx", (uint64_t)lastInsnAddr);
		if (pp.sidFirst == panda_current_asid(env) && isAddrInAnalysisSpace(lastInsnAddr) && 
				//!isAddrInAnalysisSpace(pp.pc))) {
				!isAddrInAnalysisSpace(func)) {
			fApiCalledFromModule = true;
		}
	}
	
	if (gOnlyRecordAPIsFromModule) {
		if (!fApiCalledFromModule) {
			return;
		}
	}
	/*
	if (gOnlyRecordAPIsFromModule) {
		if (prevInsnIt == gLastInsnBBHeadExec.end()) {
			return;
		}
		
		// finally, use homegrown approach instead, seems most reliable.
		lastInsnAddr = prevInsnIt->second;
		if (!(pp.cr3 == panda_current_asid(env) && isAddrInAnalysisSpace(lastInsnAddr) && 
				//!isAddrInAnalysisSpace(pp.pc))) {
				!isAddrInAnalysisSpace(func))) {
			//
			return;
		}
		
		fApiCalledFromModule = true;
		
	} else {
		if (prevInsnIt != gLastInsnBBHeadExec.end()) {
			// finally, use homegrown approach instead, seems most reliable.
			lastInsnAddr = prevInsnIt->second;
			//tracer::TrcTrace(env, TRC_BIT_DEBUG, "lastInsnAddr=%08lx", (uint64_t)lastInsnAddr);
			if (pp.cr3 == panda_current_asid(env) && isAddrInAnalysisSpace(lastInsnAddr) && 
					//!isAddrInAnalysisSpace(pp.pc))) {
					!isAddrInAnalysisSpace(func)) {
				fApiCalledFromModule = true;
			}
		}
		
	}
	*/
	if (fApiCalledFromModule) {
		assert(lastInsnAddr > 0);
		tracer::TrcTrace(env, TRC_BIT_INFO, "detect potential api call to library: caller va: "
				"%016lx, pp.pc: %016lx, func va: %016lx, lastInsnAddr=%08lx",
				pp.caller, pp.pc, func, (uint64_t)lastInsnAddr);
	}
	
	//get_api_info(CPUState* cpu, target_ulong pc, API_INFO* api_info)
	API_INFO api_info;
	int opret = ::get_api_info(env, func, &api_info);
	
	API_CALL_PARAM call_param;
	call_param.api_va = func;
	
	// Problem1: Obsidium 1.2.5.0 f has annoying feature to obscure API calls by offsetting the
	// address of called API by few bytes.
	// Problem2: Assuming that if api not found in DB, it is assumed to be Other API is
	// problematic. This might over-analysing the binary, which is risky business. Better
	// be under-analyse in this scenario, avoiding potential errornous conclusions.
	if (opret != S_W_OK) {
		// if allow all, This part generates A LOT of logs, even without DEBUG
		if (fApiCalledFromModule) {
			tracer::TrcTrace(env, TRC_BIT_WARN, "get_api_info failed, opret = %d, "
					"dll_name = %s, dll_base = %016lx", opret, api_info.module_file.c_str(), 
					(uint64_t)api_info.module_base);
		}
		//call_param.api_name = NULL;
		
	} else {
		tracer::TrcTrace(env, TRC_BIT_INFO, "func=%016lx, rva=%016lx, base=%016lx, "
				"dll_name=%s, caller=%08lx", func, api_info.fn_rva, api_info.module_base, 
				api_info.module_file.c_str(), (uint64_t)pp.caller);
		assert(func == api_info.fn_rva + api_info.module_base);
		call_param.api_name = api_info.fn_name.c_str();
		tracer::TrcTrace(env, TRC_BIT_INFO, "name=%s", call_param.api_name);
		
		gPtrEngine->onBeforeApiCall(env_param, call_param, env);
		
	}
	
	#endif
}



/**
 * @brief callback before block execution.
 * Checking for function api name is performed here, not in callstack_instr on_call
 * callback because on_call in callstack plugin is called in after_block_exec. Strangely,
 * the address given does not correspond to the first address of function, but the return
 * address after function is executed. This is useless.
 * 
 * @param env
 * @param tb
 */
int on_before_block_exec(CPUState* env, TranslationBlock* tb) {
	
	#if defined(TARGET_I386)
	
	if (!isRunningAnalysisWithAsid(env)) {
		return 0;
	}
	
	if (panda_in_kernel(env)) {
		return 0;
	}
	
	//OsiProc* p_proc = get_current_process(env);
	//OsiThread* p_thread = get_current_thread(env);
	
	//if (p_proc != NULL && p_thread != NULL) {
		//target_ptr_t asid = p_proc->asid;
		//target_pid_t tid = p_thread->tid;
		
		// remove the call checking because I realize the on_call_cb already checks it
		// via get_prog_point and checking caller and current address.
		// if marked via call, this can be useless if the call is using IAT redirection or
		// something because call does not directly sent the EIP to the addr of API func.
		//on_call_cb(env, tb->pc);
		
		//if (is_call_executed(asid, tid)) {
		//	on_call_cb(env, tb->pc);
		//	set_call_executed(asid, tid, false);
		//}
	//}
	
	//free_osiproc(p_proc);
	//free_osithread(p_thread);
	
	on_call_cb(env, tb->pc);
	
	InsnKey lastInsnKey = createLastInsnKey(panda_current_asid(env), ::get_tid(env));
	gLastInsnBBHeadExec[lastInsnKey] = tb->pc;
	
	#endif
	
	return 0;
}

bool readProcFilterConfig(const char* strAsidCsv, const char* strPidCsv, 
std::map < uint32_t, ProcFilter >& outMap, std::map < uint64_t, uint32_t >& asid2PidMap) {
	
	std::vector < std::string > asids;
	::parseCsv(strAsidCsv, CSV_SEPARATOR, asids);
	
	std::vector < std::string > pids;
	::parseCsv(strPidCsv, CSV_SEPARATOR, pids);
	
	if (asids.size() != pids.size()) {
		fprintf(stderr, "[ERROR] number of pids (%lu) and asids (%lu) does not match\n", 
			pids.size(), asids.size());
		return false;
	}
	
	int sz = asids.size();
	for (int i=0; i<sz; ++i) {
		std::string& strAsidHex = asids[i];
		std::string& strPidDec = pids[i];
		
		fprintf(stderr, " - reading asid (hex): %s, pid (dec): %s\n", 
				strAsidHex.c_str(), strPidDec.c_str());
		
		ProcFilter pf;
		sscanf(strAsidHex.c_str(), "%lx", &pf.asid);
		sscanf(strPidDec.c_str(), "%u", &pf.pid);
		
		outMap[pf.pid] = pf;
		asid2PidMap[pf.asid] = pf.pid;
	}
	
	return true;
}

bool soft_check_os_windows_7_x86() {
	return panda_os_familyno == OS_WINDOWS && panda_os_bits == 32 && 0 == strcmp(panda_os_variant, "7");
}

void hard_check_os_windows_7_x86() {
	assert(soft_check_os_windows_7_x86());
}

bool init_plugin(void * self) 
{	
#if defined(TARGET_I386)
	hard_check_os_windows_7_x86();
	
	panda_require("osi");
	assert(init_osi_api());
	panda_require("syscalls2");
	assert(init_syscalls2_api());
	panda_require("wintrospection");
	assert(init_wintrospection_api());
	panda_require("callstack_instr");
	assert(init_callstack_instr_api());
	panda_require("win7x86intro");
	assert(init_win7x86intro_api());
	panda_require("dyremoteprocwrite"); // callbacks for writes to remote processes
	// it has no public functions, just events, so, no need for inits
	panda_require("dywin7x86sp1apilogger");
	assert(init_dywin7x86sp1apilogger_api());

    panda_enable_memcb();
    panda_enable_precise_pc();

	gPtrEngine = NULL;
    gStartAnalysisAddr = 0;
    gEndAnalysisAddr = 0x10000000;
	
    panda_arg_list *args = panda_get_args(G_PLUGIN_NAME);
	
	const char * strAsidCsv = panda_parse_string(args, "asid-csv", NULL);
	if (strAsidCsv == NULL) {
		fprintf(stderr, "unable to proceed, give \"asid-csv\" for monitoring using "
				"list of asid parameter, separated by semicolon! "
                "asid is hex string without 0x\n");
        return false;
	}
	
	const char * strPidCsv = panda_parse_string(args, "pid-csv", NULL);
	if (strPidCsv == NULL) {
		fprintf(stderr, "unable to proceed, give \"pid-csv\" for monitoring using "
				"list of pid parameter, separated by semicolon! "
                "pid is decimal\n");
        return false;
	}
	
	if (!readProcFilterConfig(strAsidCsv, strPidCsv, gProcFilter, gAsid2Pid)) {
		fprintf(stderr, "[ERROR] failed parsing asid / pid configuration\n");
		return false;
	}

    gStartAnalysisAddr = (target_ulong)panda_parse_uint64_opt(
            args, "start-addr", 0, "Start address of analysis");
    gEndAnalysisAddr = (target_ulong)panda_parse_uint64_opt(
            args, "end-addr", 0x10000000, "End address (exclusive) of analysis");

    fprintf(stderr, "analysing for addresses at this range: [%08lx, %08lx)\n",
            (uint64_t)gStartAnalysisAddr, (uint64_t)gEndAnalysisAddr);

	gOnlyRecordAPIsFromModule = panda_parse_bool_opt(args, "only-from-app", "Only reports "
			"library calls from the application itself, as opposed to all calls even from "
			"other libraries or within the same library. Default: false");
	fprintf(stderr, "only-from-app is %d\n", gOnlyRecordAPIsFromModule);
	
    panda_free_args(args);

    gOutputFile = fopen(G_PLUGIN_NAME ".log", "w");
    if (gOutputFile == NULL) {
        fprintf(stderr, "[error] Unable to open log " G_PLUGIN_NAME ".log file for output\n");
        return false;
    }   

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
	
	PPP_REG_CB("syscalls2", on_NtAllocateVirtualMemory_return, on_cbNtAllocateVirtualMemory_return);
	PPP_REG_CB("syscalls2", on_NtFreeVirtualMemory_enter, on_cbNtFreeVirtualMemory_enter);
	
	//PPP_REG_CB("syscalls2", on_NtWriteVirtualMemory_return, on_cbNtWriteVirtualMemory_return);
	//PPP_REG_CB("dyremoteprocwrite", on_remote_write, on_remote_write_cb);
	PPP_REG_CB("dyremoteprocwrite", on_remote_write_ex, on_remote_write_ex_cb);
	//PPP_REG_CB("callstack_instr", on_call, on_call_mark_cb);
	
	ANALYSIS_PARAM analysis_param;
	analysis_param.asidCsv = strAsidCsv;
	analysis_param.pidCsv = strPidCsv;
	analysis_param.endAnalysisAddr = gEndAnalysisAddr;
	analysis_param.startAnalysisAddr = gStartAnalysisAddr;
	analysis_param.pEnv = &gPandaEnv;
	analysis_param.csv_separator = CSV_SEPARATOR;
	
	gPtrEngine = new AnalysisEngine(analysis_param);
	if (!gPtrEngine->init()) {
		fprintf(stderr, "[error] unable to initialize analysis engine\n");
		return false;
	}
	
    panda_cb pcb;
    pcb.virt_mem_before_write = pcbOnVirtMemWrite;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
	
    pcb.insn_translate = pcbBeforeInsnTranslate;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = pcbBeforeInsnExec;
	panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
	
	pcb.before_block_exec = on_before_block_exec;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	
	// test using onAfterInsnTranslate because somehow
	// it is possible that when BeforeInsnTranslate is called, the instruction at pc has not
	// been added to page, and as such, panda_virt_mem_read function returns failure.
/*
    pcb.after_insn_translate = pcbAfterInsnTranslate;
    panda_register_callback(self, PANDA_CB_AFTER_INSN_TRANSLATE, pcb);
*/
/*
    pcb.after_insn_exec = pcbAfterInsnExec;
    panda_register_callback(self, PANDA_CB_AFTER_INSN_EXEC, pcb);
*/
    //pcb.after_block_translate = pcbAfterBlockTranslate;
    //panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
	
	tracer::TrcInit(G_PLUGIN_NAME ".debug.log", 
			/*TRC_BIT_DEBUG |*/ TRC_BIT_INFO | TRC_BIT_WARN | TRC_BIT_ERROR, &g_trc_env);
	
    return true;

#endif
    return false;
}

void uninit_plugin(void * self) 
{
#if defined(TARGET_I386)

    if (gCapstoneOpened) {
        cs_close(&gCapstoneHandle);
    }

    if (gOutputFile != NULL) {
		gPtrEngine->dumpLogs(gOutputFile);
		fflush(gOutputFile);
		fclose(gOutputFile);
	}
    
	delete gPtrEngine;
	tracer::TrcClose();
	
#endif
}