
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

#include "dbgdefs.h"
#include "dyremoteprocwrite.h"
#include "Tracer.h"
#include "win7objecttypes.h"
#include "commons.h"

#include "SectionTable.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <set>

#include "winstruct.h"

#define G_PLUGIN_NAME "dyremoteprocwrite"

extern "C" 
{
    bool init_plugin(void *);
    void uninit_plugin(void *);
	
	PPP_PROT_REG_CB(on_remote_write);
	PPP_PROT_REG_CB(on_remote_write_ex);
}

PPP_CB_BOILERPLATE(on_remote_write);
PPP_CB_BOILERPLATE(on_remote_write_ex);

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

typedef struct _OSIPROC {
	
	uint64_t asid;
	uint32_t pid;
	uint32_t ppid;
	std::string name;
	
} OSIPROC;

std::vector < OSIPROC > processes;
std::map < uint64_t, int > asid2processIdx;
std::map < uint32_t, int > pid2processIdx;
section::SectionTable g_section_table;
PandaTrcEnv g_trc_env;

void on_proc_change_cb(CPUState *env, target_ulong asid, OsiProc *proc) {
	
	auto it = asid2processIdx.find(proc->asid);
	if (it != asid2processIdx.end()) {
		return;
	}
	
	// even with CREATE_SUSPENDED, it seems that this code is still executed before
	// the process can be used (via ZwWriteVirtualMemory / MapViewOfSection etc...) + ResumeThread
	tracer::TrcTrace(env, TRC_BIT_DEBUG, "on_proc_change_cb(asid=%016lx)", asid);
	
	OSIPROC p;
	p.asid = proc->asid;
	p.name = proc->name;
	p.pid = proc->pid;
	p.ppid = proc->ppid;
	int cidx = processes.size();
	processes.push_back(p);
	
	asid2processIdx[p.asid] = cidx;
	pid2processIdx[p.pid] = cidx;
	
	tracer::TrcTrace(env, TRC_BIT_DEBUG, "found process with asid=%lx, pid=%d", p.asid, p.pid);
}

void cb_on_remote_write(REMOTE_WRITE& param) {
	
	tracer::TrcTrace(param.cpu, TRC_BIT_DEBUG, ">> cb_on_remote_write()");
	tracer::TrcTrace(param.cpu, TRC_BIT_DEBUG, "\tsource_asid=%016lx", param.source_asid);
	tracer::TrcTrace(param.cpu, TRC_BIT_DEBUG, "\tsource_pc=%016lx", param.source_pc);
	tracer::TrcTrace(param.cpu, TRC_BIT_DEBUG, "\ttarget_asid=%016lx", param.target_asid);
	tracer::TrcTrace(param.cpu, TRC_BIT_DEBUG, "\ttarget_addr=%016lx", param.target_addr);
	tracer::TrcTrace(param.cpu, TRC_BIT_DEBUG, "\twrite size=%u", param.target_write_size);
	tracer::TrcTrace(param.cpu, TRC_BIT_DEBUG, "\tsource_tid=%d", param.source_tid);
	
	//PPP_RUN_CB(on_remote_write, (CPUState*)param.cpu, param.source_asid, param.source_pc, 
	//		param.target_asid, param.target_addr, param.target_write_size, param.target_write_bytes);
	PPP_RUN_CB(on_remote_write_ex, &param);
	
	tracer::TrcTrace(param.cpu, TRC_BIT_DEBUG, "<< cb_on_remote_write()");
	
}

/*NTSYSAPI 
NTSTATUS
NTAPI


NtWriteVirtualMemory(



  IN HANDLE               ProcessHandle,
  IN PVOID                BaseAddress,
  IN PVOID                Buffer,
  IN ULONG                NumberOfBytesToWrite,
  OUT PULONG              NumberOfBytesWritten OPTIONAL );*/
void on_cbNtWriteVirtualMemory_return(
			CPUState *cpu, target_ulong pc, uint32_t ProcessHandle, 
			uint32_t BaseAddress, uint32_t Buffer, uint32_t BufferSize, 
			uint32_t NumberOfBytesWritten) {
	//
	#if defined(TARGET_I386)
	
	CPUArchState * cpuarch = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
	uint32_t retval = cpuarch->regs[R_EAX];
	
	RR_prog_point pp = rr_prog_point();
	target_ulong asid = panda_current_asid(cpu);
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "NtWriteVirtualMemory(asid=0x%x, pc=0x%x, "
		"ProcessHandle=0x%x, BaseAddress=0x%x, Buffer=0x%x, BufferSize=0x%x, "
		"NumberOfBytesWritten=0x%x); instrcnt=%lu; returns %u", (uint32_t)asid, (uint32_t)pc, 
		ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten, 
		(uint64_t) pp.guest_instr_count, retval);
	
	if (retval != NTSTATUS_SUCCESS) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "syscall failed");
		return;
	}
	
	uint32_t target_pid = process_handle_to_pid(cpu, ProcessHandle);
	
	if (target_pid == 0) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "target_pid not found (0)");
		return;
	}
	
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "---- target_pid = %u", target_pid);
			
	auto pit = pid2processIdx.find(target_pid);
	
	// issue here, if WriteProcessMemory performed by executables whose already switched before
	// the recording starts, it won't be found here, obviously!
	
	// so, just ignore if the process has not been analysed yet. Most likely that is not
	// the interesting process we want from the recording anyway...
	// why would you like to start recording after the targeted process has been executed anyway???
	if (pit != pid2processIdx.end()) {
		uint64_t target_asid = processes[pit->second].asid;
		
		if (NumberOfBytesWritten != 0) { // NumberOfBytesWritten is a pointer.
			uint32_t nb = 0;
			if (-1 != panda_virtual_memory_read(cpu, NumberOfBytesWritten, 
			(uint8_t*)(&nb), sizeof(nb))) {
				tracer::TrcTrace(cpu, TRC_BIT_DEBUG, " - *NumberOfBytesWritten=%u", nb);
				BufferSize = nb;
			}
		}
	
		std::vector < uint8_t > vbuf(BufferSize);
		
		// no need to check the buffers, they're optional (currently)
		panda_virtual_memory_read(cpu, Buffer, &vbuf[0], (int)BufferSize);
		
		REMOTE_WRITE rm;
		rm.cpu = cpu;
		rm.source_asid = panda_current_asid(cpu);
		rm.source_pc = ::find_caller_in_process_module(cpu);
		rm.source_tid = ::get_tid(cpu);
		rm.target_addr = BaseAddress;
		rm.target_asid = target_asid;
		rm.target_write_bytes = &vbuf[0];
		rm.target_write_size = BufferSize;
		
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "---- target_pid = %u, target_asid = %08lx", 
				target_pid, target_asid);
		
		cb_on_remote_write(rm);
		
	}
	
	#endif
}


// SectionHandle == pointer to HANDLE (out variable)
// ObjectAttributes == pointer to object attribute structure
/*NTSYSAPI 
NTSTATUS
NTAPI


NtCreateSection(



  OUT PHANDLE             SectionHandle,
  IN ULONG                DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
  IN PLARGE_INTEGER       MaximumSize OPTIONAL,
  IN ULONG                PageAttributess,
  IN ULONG                SectionAttributes,
  IN HANDLE               FileHandle OPTIONAL );
 */ 
void on_cbNtCreateSection_return(CPUState *cpu, target_ulong pc, 
uint32_t SectionHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, 
uint32_t MaximumSize, uint32_t SectionPageProtection, 
uint32_t AllocationAttributes, uint32_t FileHandle) {
	#if defined(TARGET_I386)
	
	CPUArchState * cpuarch = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
	uint32_t retval = cpuarch->regs[R_EAX];
	
	RR_prog_point pp = rr_prog_point();
	target_ulong asid = panda_current_asid(cpu);
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "NtCreateSection(asid=0x%x, pc=0x%x, "
		"SectionHandle=0x%x, DesiredAccess=0x%x, ObjectAttributes=0x%x, MaximumSize=0x%x, "
		"SectionPageProtection=0x%x, AllocationAttributes=0x%x, FileHandle=0x%x); instrcnt=%lu; returns %u", 
		(uint32_t)asid, (uint32_t)pc, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, 
		AllocationAttributes, FileHandle, (uint64_t) pp.guest_instr_count, retval);
	
	if (retval != NTSTATUS_SUCCESS) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "syscall failed");
		return;
	}
	
	uint32_t section_handle_val = 0;
	if (-1 == panda_virtual_memory_read(cpu, SectionHandle, 
	(uint8_t*)(&section_handle_val), sizeof(section_handle_val))) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "unable to read section handle at %x", SectionHandle);
		return;
	}
	
	std::string section_name;
	if (ObjectAttributes != 0 && !extract_string_from_object_attributes(cpu, ObjectAttributes, section_name)) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "unable to read ObjectAttributes name at %x", ObjectAttributes);
		return;
	}
	
	// section name empty should be handled also, for simplicity
	//if (section_name == "") {
	//	tracer::TrcTrace(TRC_BIT_DEBUG, "section name empty");
	//	return;
	//}
	assert(g_section_table.create_new_section(panda_current_asid(cpu), 
			section_handle_val, section_name.c_str(), cpu, 
			::find_caller_in_process_module(cpu), ::get_tid(cpu)));
	
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Creation section success(asid=%08lx, handle=%x, name=%s)", 
			(uint64_t)asid, section_handle_val, section_name.c_str());
	
	#endif
}

/*
NTSYSAPI 
NTSTATUS
NTAPI


NtMapViewOfSection(



  IN HANDLE               SectionHandle,
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress OPTIONAL,
  IN ULONG                ZeroBits OPTIONAL,
  IN ULONG                CommitSize,
  IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
  IN OUT PULONG           ViewSize,
  IN                      InheritDisposition,
  IN ULONG                AllocationType OPTIONAL,
  IN ULONG                Protect );
 * 
 */ 
void on_cbNtMapViewOfSection_return(CPUState *cpu, target_ulong pc, 
uint32_t SectionHandle, uint32_t ProcessHandle, uint32_t BaseAddress, 
uint32_t ZeroBits, uint32_t CommitSize, uint32_t SectionOffset, 
uint32_t ViewSize, uint32_t InheritDisposition, uint32_t AllocationType, 
uint32_t Win32Protect) {
	#if defined(TARGET_I386)
	// treat this the same way as write to remote / current process using 
	// NtWriteVirtualMemory instead.
	
	CPUArchState * cpuarch = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
	uint32_t retval = cpuarch->regs[R_EAX];
	
	RR_prog_point pp = rr_prog_point();
	target_ulong asid = panda_current_asid(cpu);
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "NtMapViewOfSection(asid=0x%x, pc=0x%x, SectionHandle=0x%x, ProcessHandle=0x%x, "
			"BaseAddress=0x%x, ZeroBits=0x%x, CommitSize=0x%x, SectionOffset=0x%x, ViewSize=0x%x, "
			"InheritDisposition=0x%x, AllocationType=0x%x, Win32Protect=0x%x) => %x; instrcnt=%llu", 
			(uint32_t)asid, (uint32_t)pc, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, 
			CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, 
			Win32Protect, retval, (unsigned long long int) pp.guest_instr_count);
	
	if (retval != NTSTATUS_SUCCESS) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "syscall failed");
		return;
	}
	
	target_ulong target_pid = process_handle_to_pid(cpu, ProcessHandle);
	
	if (target_pid == 0) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "failed finding target_pid from ProcessHandle");
		return;
	}
	
	// target process: ProcessHandle
	// start address: BaseAddress
	// size: ViewSize
	
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "---- target_pid = %u", target_pid);
			
	auto pit = pid2processIdx.find(target_pid);
	
	if (pit != pid2processIdx.end()) {
		uint64_t target_asid = processes[pit->second].asid;
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "target_asid found: %lx", target_asid);
		
		target_ulong base_addr = 0;
		if (-1 == panda_virtual_memory_read(cpu, BaseAddress, 
		(uint8_t*)(&base_addr), sizeof(base_addr))) {
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Failed reading BaseAddress value at %x", BaseAddress);
			return;
		}
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "BaseAddress read: %lx", base_addr);
		
		target_ulong section_size = 0;
		if (-1 == panda_virtual_memory_read(cpu, ViewSize, 
		(uint8_t*)(&section_size), sizeof(section_size))) {
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "failed reading ViewSize value at %x", ViewSize);
			return;
		}
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "ViewSize read: %lx", section_size);
		
		std::vector < uint8_t > vbuf(section_size);
		
		// no need to check the buffers, they're optional (currently)
		panda_virtual_memory_read(cpu, base_addr, &vbuf[0], (int)section_size);
		
		// if no section global recorded, probably is currently handling uninteresting process.
		// this should be common on early recording where the create/open section is not recorded.
		// just ignore these.
		// usually this happen if section is opened / created before mapping it.
		// this could happen as expected if the section is mapped from other process.
		// the section is opened in current process. Other process does not have to open it! I forget this!!!
        // move this code to SectionTable but instead of fail if not opened, open it, then continues execution.
		if (!g_section_table.map_section_to_process(asid, SectionHandle,
					target_asid, base_addr, section_size, cpu)) {
			//
			tracer::TrcTrace(cpu, TRC_BIT_WARN, "no section found for asid=%lx, SectionHandle=%x"
					" usually this is because the create/open section syscall is included in recording", 
					(uint64_t)asid, SectionHandle);
			return;
		}
		
		const section::SECTION_GLOBAL_ENTRY* p_sge = g_section_table
				.find_section_global_entry_by_base_addr(target_asid, base_addr);
		
		// must check for each byte for section_size
		// find the memory for each, check the last process that writes them
		
		if (p_sge->creator_exec.asid == asid && asid == target_asid) {
			// NOP here
			// create own section and mapped it to my own.
			// <removed>
			// If the program writes to section mapped to current process, then map it elsewhere,
			// and remote process modified it
			// then both process should have their process memory modified.
			// ... OK, this case has been handled actually.
			// I forget that the proceeding codes are simply on_remote_write events, so
			// irrelevant.
			// </removed>
			return;
		}
		
		if (p_sge->creator_exec.asid == asid) {
			// map section to different process here:
			
			REMOTE_WRITE rm;
			rm.cpu = cpu;
			rm.source_asid = asid;
			rm.source_pc = ::find_caller_in_process_module(cpu);
			rm.source_tid = ::get_tid(cpu);
			rm.target_addr = base_addr;
			rm.target_asid = target_asid;
			rm.target_write_bytes = &vbuf[0];
			rm.target_write_size = section_size;
			
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Map from own section to different process, base_addr = %08lx,"
					" section_size = %08lx, target_pid = %u, target_asid = %08lx", 
					(uint64_t)base_addr, (uint64_t)section_size, target_pid, target_asid);
			
			cb_on_remote_write(rm);
			
			return;
			
		} else if (asid != target_asid) {
			// section is created by other process. This process opens it and maps it elsewhere
			// what to make of this??
			// assume current process writes to other process.
			
			REMOTE_WRITE rm;
			rm.cpu = cpu;
			rm.source_asid = asid;
			rm.source_pc = ::find_caller_in_process_module(cpu);
			rm.source_tid = ::get_tid(cpu);
			rm.target_addr = base_addr;
			rm.target_asid = target_asid;
			rm.target_write_bytes = &vbuf[0];
			rm.target_write_size = section_size;
			
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Map from other process section to different process, base_addr = %08lx,"
					" section_size = %08lx, target_pid = %u, target_asid = %08lx", 
					(uint64_t)base_addr, (uint64_t)section_size, target_pid, target_asid);
			
			cb_on_remote_write(rm);
			
			return;
			
		} else {
			// section is created by other process and it is mapped here, by this process
			// might be using NtOpenSection with specified section name.
			
			REMOTE_WRITE rm;
			rm.cpu = cpu;
			rm.source_asid = p_sge->creator_exec.asid;
			rm.source_pc = p_sge->creator_exec.insn_addr;
			rm.source_tid = p_sge->creator_exec.tid;
			rm.target_addr = base_addr;
			rm.target_asid = target_asid;
			rm.target_write_bytes = &vbuf[0];
			rm.target_write_size = section_size;
			
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Map from other process section to own process, base_addr = %08lx,"
					" section_size = %08lx, target_pid = %u, target_asid = %08lx", 
					(uint64_t)base_addr, (uint64_t)section_size, target_pid, target_asid);
			
			cb_on_remote_write(rm);
			
			return;
			
		}
		
		
		
	}
	
	
	#endif
}

/*NTSYSAPI 
NTSTATUS
NTAPI


NtUnmapViewOfSection(



  IN HANDLE               ProcessHandle,
  IN PVOID                BaseAddress );*/
void on_cbNtUnmapViewOfSection_return(CPUState *cpu, target_ulong pc, 
uint32_t ProcessHandle, uint32_t BaseAddress) {
#ifdef TARGET_I386
	CPUArchState * cpuarch = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
	uint32_t retval = cpuarch->regs[R_EAX];
	
	RR_prog_point pp = rr_prog_point();
	target_ulong asid = panda_current_asid(cpu);
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "NtUnmapViewOfSection(asid=0x%x, pc=0x%x, ProcessHandle=0x%x, "
			"BaseAddress=0x%x) => 0x%x; instrcnt=%llu", (uint32_t)asid, (uint32_t)pc, 
			ProcessHandle, BaseAddress, retval, (unsigned long long int) pp.guest_instr_count);
	
	if (retval != NTSTATUS_SUCCESS) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "syscall failed");
		return;
	}
	
	target_ulong target_pid = process_handle_to_pid(cpu, ProcessHandle);
	
	if (target_pid == 0) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Unable to find pid from ProcessHandle");
		return;
	}
	
	// target process: ProcessHandle
	// start address: BaseAddress
	// size: ViewSize
	
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "---- target_pid = %u", target_pid);
			
	auto pit = pid2processIdx.find(target_pid);
	
	if (pit != pid2processIdx.end()) {
		uint64_t target_asid = processes[pit->second].asid;
		
		const section::SECTION_PROCESS_ENTRY* p_spe = 
				g_section_table.find_section_by_base_addr(target_asid, BaseAddress);
		if (p_spe == NULL) {
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "No section mapped for asid=%lx, BaseAddress=%x",
					(uint64_t)target_asid, BaseAddress);
			return;
		}
		//assert(p_spe != NULL);
		
		std::vector < uint8_t > vbuf(p_spe->size); 
		
		REMOTE_WRITE rm;
		rm.cpu = cpu;
		rm.source_asid = panda_current_asid(cpu);
		rm.source_pc = ::find_caller_in_process_module(cpu);
		rm.source_tid = ::get_tid(cpu);
		rm.target_addr = BaseAddress;
		rm.target_asid = target_asid;
		rm.target_write_bytes = &vbuf[0]; // all zeros.
		rm.target_write_size = p_spe->size;
		
		// unmapping is effectively the same as rewriting the buffer with all zeros.
		
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "---- base_addr = %08lx, section_size = %08lx, "
				"target_pid = %u, target_asid = %08lx", 
				(uint64_t)rm.target_addr, (uint64_t)rm.target_write_size, target_pid, rm.target_asid);
		
		cb_on_remote_write(rm);
		
		assert(g_section_table.unmap_section_in_process(target_asid, BaseAddress, cpu));
		
	}
	
	
#endif
}

// SectionHandle is pointer to handle (out variable)
// ObjectAttributes contain the searched section name
/*NTSYSAPI 
NTSTATUS
NTAPI


NtOpenSection(



  OUT PHANDLE             SectionHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes );*/
void on_cbNtOpenSection_return(CPUState *cpu, target_ulong pc, 
uint32_t SectionHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes) {
#ifdef TARGET_I386
	CPUArchState * cpuarch = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
	uint32_t retval = cpuarch->regs[R_EAX];
	
	target_ulong asid = panda_current_asid(cpu);
	RR_prog_point pp = rr_prog_point();
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "NtOpenSection(asid=0x%x, pc=0x%x, SectionHandle=0x%x, "
			"DesiredAccess=0x%x, ObjectAttributes=0x%x) => 0x%x; instrcnt=%llu", 
			(uint32_t)asid, (uint32_t)pc, SectionHandle, DesiredAccess, 
			ObjectAttributes, retval, (unsigned long long int) pp.guest_instr_count);
	
	if (retval != NTSTATUS_SUCCESS) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "syscall failed");
		return;
	}
	
	std::string section_name;
	if (!extract_string_from_object_attributes(cpu, ObjectAttributes, section_name)) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Unable to read ObjectAttributes at %x", ObjectAttributes);
		return;
	}
	
	target_ulong section_handle_val = 0;
	if (-1 == panda_virtual_memory_read(cpu, SectionHandle, 
	(uint8_t*)(&section_handle_val), sizeof(section_handle_val))) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Unable to read SectionHandle at %x", SectionHandle);
		return;
	}
	
	target_ulong current_asid = panda_current_asid(cpu);
	
	if (!g_section_table.open_section(current_asid, section_handle_val, section_name.c_str(), cpu)) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Unable to find section info. NtCreateSection "
				"has not been monitored previously. Recording too late? SectionName=%s, "
				"current_asid=%lx, section_handle=%x", section_name.c_str(), current_asid, section_handle_val);
		return;
	}
	
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "Section successfully opened(section=%x, name=%s)", 
			section_handle_val, section_name.c_str());
	
#endif
}

// handle individual writes to the mapped sections.
int virt_mem_before_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
	#if defined(TARGET_I386)
	
	if (panda_in_kernel(env)) {
		return 0;
	}
	
	target_ulong current_asid = panda_current_asid(env);
	
	std::vector < section::SECTION_WRITE_ENTRY > out;
	bool found = g_section_table.find_all_mapped_sections(current_asid, addr, size, out, env);
	if (!found) {
		return 0;
	}
	
	uint32_t current_tid = ::get_tid(env);
	uint32_t len = out.size();
	for (uint32_t i = 0; i < len; ++i) {
		if (out[i].asid != current_asid) {
			REMOTE_WRITE rm;
			rm.target_write_size = out[i].size;
			rm.source_asid = current_asid;
			rm.target_addr = out[i].addr;
			rm.source_pc = ::find_caller_in_process_module(env);
			rm.source_tid = current_tid;
			rm.target_asid = out[i].asid;
			rm.cpu = env;
			rm.target_write_bytes = (uint8_t*) buf;
			cb_on_remote_write(rm);
		}
	}
	
	#endif
	return 0;
}

bool init_plugin(void * self) {
	#if defined(TARGET_I386)
	
	hard_check_os_windows_7_x86();
	
	tracer::TrcInit(G_PLUGIN_NAME ".debug.log", 31, &g_trc_env);
	
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
	panda_require("asidstory");
	
	panda_enable_memcb();
	panda_enable_precise_pc();
	
	if (!g_section_table.init()) {
		tracer::TrcTrace(TRC_BIT_ERROR, "Failed initialize g_section_table");
		return false;
	}
	
	PPP_REG_CB("syscalls2", on_NtWriteVirtualMemory_return, on_cbNtWriteVirtualMemory_return);
	PPP_REG_CB("syscalls2", on_NtOpenSection_return, on_cbNtOpenSection_return);
	PPP_REG_CB("syscalls2", on_NtUnmapViewOfSection_return, on_cbNtUnmapViewOfSection_return);
	PPP_REG_CB("syscalls2", on_NtMapViewOfSection_return, on_cbNtMapViewOfSection_return);
	PPP_REG_CB("syscalls2", on_NtCreateSection_return, on_cbNtCreateSection_return);
	PPP_REG_CB("asidstory", on_proc_change, on_proc_change_cb);
	
	panda_cb pcb;
	pcb.virt_mem_before_write = virt_mem_before_write;
	panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
	
	return true;
	#endif
	return false;
}

void uninit_plugin(void * self) {
	#if defined(TARGET_I386)
	g_section_table.uninit();
	tracer::TrcClose();
	#endif
}
