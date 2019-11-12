#include "AnalysisEngine.h"
#include "win32peheader.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "api_filter.h"
#include "Tracer.h"

// For writes to remote process:
// better just hook ZwWriteVirtualMemory instead.
// use function from wintrospection.c, it might be possible to get PID from ProcessHandle
// also test for write to remote process. What happened during that time in onBeforeVirtualMemoryWrite function??
// how cr3 changed, etc. 

// try this:
// get_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle)
// eproc is current process
// handle if the ProcessHandle from ZwWriteVirtualMemory
// after that,
// obtain return value, find the pObj.
// the pObj seems to be the address of EPROC kernel struct. There's get_pid(CPUState*env, eproc) in wintrospection.

// in order to make analysis much faster,
// in function onBeforeVirtWrite, only allow for both target addr and instr addr to be within analysis range.
// For remote writes, just hook syscall ZwWriteVirtualMemory instead.

/**
 * @brief Creates addr key for writes and transitions
 * @param pid
 * @param layer_num
 * @param addr
 */
TRIPLET(proccess_id_t, layer_t, addr_t) createAddrKey(proccess_id_t pid, layer_t layer_num, addr_t addr) {
	TRIPLET(proccess_id_t, layer_t, addr_t) tp;
	tp.first = pid;
	tp.second.first = layer_num;
	tp.second.second = addr;
	return tp;
}

// tested
/**
 * @brief Split tokens separated by separator char
 * @param csv csv string
 * @param separator separator character
 * @param out
 * @return true if success, false otherwise
 */
bool parseCsv(const char * csv, char separator, std::vector < std::string >& out) {
	
	std::string strCsv(csv);
	
	const char * pBegin = csv;
	const char * pEnd = ::strchr(pBegin, separator);

	while (pEnd != NULL) {
		std::string substr = strCsv.substr((int)(pBegin - csv), (int)(pEnd - pBegin));
		out.push_back(substr);

		pBegin = pEnd + 1; // skipping separator
		pEnd = ::strchr(pBegin, separator);
	}

	// add the last segment
	std::string substr = strCsv.substr((int)(pBegin - csv));
	out.push_back(substr);

	return true;
}

/**
 * @brief Check if str is hex, does not support 0x header
 * @param str
 * @return 
 */
bool isHex(const char * str) {
	int len = strlen(str);
	if (len == 0) {
		return false;
	}

	for (int i=0; i<len; ++i) {
		if (!(
			(str[i] >= '0' && str[i] <= '9') || 
			(str[i] >= 'a' && str[i] <= 'f') || 
			(str[i] >= 'A' && str[i] <= 'F'))
			) {
			return false;
		}
	}

	return true;
}

/**
 * @brief Checks if str is a decimal number. Leading zeros is allowed
 * @param str
 * @return 
 */
bool isDec(const char * str) {
	int len = strlen(str);
	if (len == 0) {
		return false;
	}

	for (int i=0; i<len; ++i) {
		if (str[i] < '0' || str[i] > '9') {
			return false;
		}
	}

	return true;
}

/**
 * @brief Convert MEMLOC enum to string code.
 * @param mem_loc
 * @return 
 */
const char * mem_location_to_string(MEMLOC mem_loc) {
	switch (mem_loc) {
	case MEMLOC_UNKNOWN:
		return "X";
	break;
	
	case MEMLOC_HEAP:
		return "H";
	break;
	
	case MEMLOC_LIB:
		return "L";
	break;
	
	case MEMLOC_MODULE:
		return "M";
	break;
	
	case MEMLOC_STACK:
		return "S";
	break;
	
	case MEMLOC_INIT:
		return "??";
	break;
	
	default:
	assert(0);
	break;
	}

	return "???";
}

IEnvironment::IEnvironment() {
	// NOP
}

IEnvironment::~IEnvironment() {
	// NOP
}

AnalysisEngine::AnalysisEngine(const ANALYSIS_PARAM& param)
: mStrPidCsv(param.pidCsv),
mStrAsidHexCsv(param.asidCsv),
mEnv(*param.pEnv),
mInitialized(false),
mAsid2Pid(),
mProcesses(),
mStartAnalysisAddr(param.startAnalysisAddr),
mEndAnalysisAddr(param.endAnalysisAddr),
mGlobalLastInsn(),
mGlobalLastInsnIsSet(false),
mCsvSeparator(param.csv_separator)
{

}

AnalysisEngine::~AnalysisEngine() {
	
}

// tested
bool AnalysisEngine::init() {
	if (!this->mInitialized) {
		bool ret;
		
		ret = this->_readConfig(this->mStrAsidHexCsv.c_str(), this->mStrPidCsv.c_str());
		assert(ret);

		this->mInitialized = ret;
	}
	return this->mInitialized;
}

// tested
bool AnalysisEngine::_readConfig(const char * hexAsidCsv, const char * pidDecCsv) {
	
	std::vector < std::string > hexAsid;
	parseCsv(hexAsidCsv, this->mCsvSeparator, hexAsid);

	std::vector < std::string > decPid;
	parseCsv(pidDecCsv, this->mCsvSeparator, decPid);

	assert(hexAsid.size() == decPid.size());
	if (hexAsid.size() != decPid.size()) {
		return false;
	}

	assert(hexAsid.size() > 0);

	for (uint32_t i=0; i<hexAsid.size(); ++i) {
		
		assert(isHex(hexAsid[i].c_str()));
		addr_t asid = 0;
		sscanf(hexAsid[i].c_str(), "%lx", &asid);

		assert(isDec(decPid[i].c_str()));
		proccess_id_t pid = 0;
		sscanf(decPid[i].c_str(), "%u", &pid);

		this->mAsid2Pid[asid] = pid;

		PROCESS_DATA pd;
		pd.asid = asid;
		pd.pid = pid;
		this->mProcesses[pid] = pd;

	}

	return true;

}

// tested
layer_t AnalysisEngine::_getHighestLayer(
const std::map < addr_t, SHADOW_BYTE >& shadowMemory, 
addr_t addr, 
uint32_t size) const {
	layer_t lmax = 0;
	for (uint32_t i=0; i<size; ++i) {
		auto it = shadowMemory.find(addr + i);
		if (it != shadowMemory.end()) {
			const SHADOW_BYTE& sb = it->second;
			if (lmax < sb.layerNumber) {
				lmax = sb.layerNumber;
			}
		}
	}
	return lmax;
}

// return 0 = false, 1 = true
int AnalysisEngine::onBeforeInsnTranslate(const EXEC_ENV_PARAM& execParam, const INS_PARAM& insParam, void* p) {
	assert(this->mInitialized);

	// 
	auto asid2pidIt = this->mAsid2Pid.find(execParam.asid);
	if (asid2pidIt == this->mAsid2Pid.end()) {
		return 0;
	}
	
	assert(insParam.addr > 0 && insParam.size > 0 && insParam.buf != NULL);
	if (!this->_execInAnalysisAddr(insParam.addr)) {
		return 0;
	}
	
	// bug here, under assumption of multiple process analysis, 
	// PID = current process, asid = target one.
	//proccess_id_t configPid = asid2pidIt->second;
	//PROCESS_DATA& processData = this->mProcesses[configPid];
	PROCESS_DATA& processData = this->mProcesses[execParam.pid];

	// partial code modification counts for entire code modification.
	layer_t executingLayer = this->_getHighestLayer(processData.shadowMemory, insParam.addr, insParam.size);
	PROCESS_LAYER& processLayer = processData.layers[executingLayer];
	processLayer.layerNumber = executingLayer;
	
	// what's this for? unused.
	/*
	for (uint32_t i=0; i<insParam.size; ++i) {
		addr_t xaddr = insParam.addr + i;

		auto xit = processLayer.executed.find(xaddr);
		if (xit != processLayer.executed.end()) {
			// this is suspect.
			// there might be the case if some instructions are retranslated again because 
			// QEMU translation buffer is full. If the instruction is rewritten, they will be 
			// in a different layer. Not here. If the layer is the same but retranslated, it means
			// that QEMU simply exhausted its translation buffers and clean them all up, thus forcing
			// retranslating everything. In this case, just ignore it and reuse existing.
			// still NOP for now
			
			// problem if the code is rewritten by other at same layer. By definition,
			// if a packer engine unpacks different code at the same memory region, 
			// they will have same address, but different code, but same layer, 
			
			// ANS: there should be no problem. PROCESS_EXECUTED_BYTE does not hold any specific information
			// about instruction themselves. It just record what writes has been performed by ANY
			// instruction in this address. If the instr is rewritten, so be it. This struct
			// just does not care. The existing write records will still be there and just
			// will be appended by writes by new instructions.
		}

		//PROCESS_EXECUTED_BYTE& pxb = processLayer.executed[xaddr];
	}
	*/

	// add the absent instructions, if any
	this->_add_instruction_to_layer(insParam, processLayer, processData);
	
	for (uint32_t i=0; i<insParam.size; ++i) {
		addr_t xaddr = insParam.addr + i;

		auto xit = processLayer.executed.find(xaddr);
		assert(xit != processLayer.executed.end());
		PROCESS_EXECUTED_BYTE& pxb = xit->second;
		pxb.memLoc = this->_get_mem_location(execParam.asid, xaddr, p);
	}

	return 1;
}

void AnalysisEngine::_add_instruction_to_layer(const INS_PARAM& insParam, 
PROCESS_LAYER& current_layer, PROCESS_DATA& current_process) {
	
	assert(insParam.addr > 0);
	assert(insParam.size > 0);
	assert(insParam.buf != NULL);
	
	for (uint32_t i = 0; i < insParam.size; ++i) {
		addr_t xaddr = insParam.addr + i;

		auto xit = current_layer.executed.find(xaddr);
		if (xit == current_layer.executed.end()) {
			PROCESS_EXECUTED_BYTE exb;
			exb.addr = xaddr;
			current_layer.executed[xaddr] = exb;
		}
	}

	if (insParam.size > 0) {
		INSN_INFO& ii = current_process.insnInfos[insParam.addr];
		ii.addr = insParam.addr;
		ii.size = insParam.size;
		assert(insParam.buf != NULL);
		assert(sizeof(ii.buf) >= ii.size);
		memcpy(ii.buf, insParam.buf, ii.size);
	}
	
	for (uint32_t i = 0; i < insParam.size; ++i) {
		current_process.insnHead[insParam.addr + i] = insParam.addr;
	}

}

void AnalysisEngine::_updateGLobalLastInsn(const PROCESS_LAST_INSTRUCTION& last) {
	this->mGlobalLastInsn = last;
	this->mGlobalLastInsnIsSet = true;
}

int AnalysisEngine::onBeforeInsnExec(const EXEC_ENV_PARAM& execParam, const INS_PARAM& usInsParam, void* p) {
	assert(this->mInitialized);

	auto asid2pidIt = this->mAsid2Pid.find(execParam.asid);
	if (asid2pidIt == this->mAsid2Pid.end()) {
		return 0;
	}

	assert(usInsParam.addr > 0);
	if (!this->_execInAnalysisAddr(usInsParam.addr)) {
		return 0;
	}

	// record last instruction and transitions
	PROCESS_DATA& proc_data = this->mProcesses[execParam.pid];
	INS_PARAM insParam = this->_ins_param_with_db_check(proc_data, usInsParam);
	layer_t executing_layer = this->_getHighestLayer(proc_data.shadowMemory, insParam.addr, insParam.size);
	PROCESS_LAYER& plx_layer = proc_data.layers[executing_layer];
	plx_layer.layerNumber = executing_layer;
	PROCESS_EXECUTED_BYTE& xb = plx_layer.executed[insParam.addr];
	guest_insncnt_t insncnt = this->mEnv.read_guest_insnctr(p);
	
	xb.pp_range.addAddr(insncnt);
	//xb.memLoc = this->_get_mem_location(execParam.asid, insParam.addr, p);
	
	//this->_markExecuted(execParam.asid, insParam.addr, insParam.size);
	this->_markExecuted(execParam, insParam, p);
	
	// check for inter-process transition, via compare with global last instruction
	// note, this might not actually transition but simply process scheduling
	if (this->mGlobalLastInsnIsSet && this->mGlobalLastInsn.owner_asid != execParam.asid) {
		
		// last instruction at different CR3, transition from different process.
		TRIPLET(proccess_id_t, layer_t, addr_t) transition_key = createAddrKey(
				this->mGlobalLastInsn.owner_pid, 
				this->mGlobalLastInsn.layer, 
				this->mGlobalLastInsn.addr);
		xb.transitionCounters[transition_key] += 1;

	}
	
	// continue checking for transition from last instruction in the thread

	auto li_it = proc_data.lastInstrs.find(execParam.tid);
	if (li_it == proc_data.lastInstrs.end()) {
		// first instruction, just initialize and exit
		PROCESS_LAST_INSTRUCTION li;
		li.addr = insParam.addr;
		li.size = insParam.size;
		li.layer = executing_layer;
		li.owner_asid = execParam.asid;
		li.owner_pid = execParam.pid;
		li.insncnt = insncnt;
		proc_data.lastInstrs[execParam.tid] = li;
		this->_updateGLobalLastInsn(li);
		return 0;
	}

	PROCESS_LAST_INSTRUCTION& last_insn = li_it->second;

	if (executing_layer == last_insn.layer) {
		// instruction transition from same layer, update to current instruction and ignore
		last_insn.addr = insParam.addr;
		last_insn.size = insParam.size;
		last_insn.owner_asid = execParam.asid;
		last_insn.owner_pid = execParam.pid;
		last_insn.insncnt = insncnt;
		this->_updateGLobalLastInsn(last_insn);
		return 0;
	}

	// transition from different layer. record it!
	TRIPLET(proccess_id_t, layer_t, addr_t) transition_key = createAddrKey(
			last_insn.owner_pid, last_insn.layer, last_insn.addr);
	xb.transitionCounters[transition_key] += 1;

	// update last instruction of a thread
	last_insn.layer = executing_layer;
	last_insn.addr = insParam.addr;
	last_insn.size = insParam.size;
	last_insn.owner_asid = execParam.asid;
	last_insn.owner_pid = execParam.pid;
	last_insn.insncnt = insncnt;
	this->_updateGLobalLastInsn(last_insn);

	return 0;
}

// not used now
int AnalysisEngine::onAfterInsnTranslate(const EXEC_ENV_PARAM& execParam, const INS_PARAM& insParam, void* p) {
	assert(this->mInitialized);
	fprintf(stderr, "AnalysisEngine::onAfterInsnTranslate Function unsupported\n");
	assert(false);
	return 0;
}

// not used now
int AnalysisEngine::onAfterInsnExec(const EXEC_ENV_PARAM& execParam, const INS_PARAM& insParam, void* p) {
	assert(this->mInitialized);
	fprintf(stderr, "AnalysisEngine::onAfterInsnExec Function unsupported\n");
	assert(false);
	return 0;
}

bool AnalysisEngine::_execInAnalysisAddr(addr_t addr) const {
	return this->isInAnalysisSpace(addr);
	//return addr >= this->mStartAnalysisAddr && addr < this->mEndAnalysisAddr;
}

bool AnalysisEngine::_writeInAnalysisAddr(addr_t addr) const {
	return this->_execInAnalysisAddr(addr);
}

bool AnalysisEngine::isInAnalysisSpace(addr_t addr) const {
	return addr >= this->mStartAnalysisAddr && addr < this->mEndAnalysisAddr;
}

bool AnalysisEngine::isAnalyzePid(proccess_id_t pid) const {
	return this->mProcesses.find(pid) != this->mProcesses.end();
}
	
bool AnalysisEngine::isAnalyzeAsid(asid_t asid) const {
	return this->mAsid2Pid.find(asid) != this->mAsid2Pid.end();
}
	
bool AnalysisEngine::isInUserAddrSpace(addr_t addr) const {
	return addr < KERNEL_START_ADDR;
}

int AnalysisEngine::onBeforeWriteVirtAddr(asid_t target_process_asid, 
const EXEC_ENV_PARAM& execParam, const INS_PARAM& usInsParam, 
const WRITE_PARAM& writeParam, void* p)
{
	assert(this->mInitialized);

	auto asid2pidIt = this->mAsid2Pid.find(target_process_asid);
	if (asid2pidIt == this->mAsid2Pid.end()) {
		return 0;
	}

	if (!this->_writeInAnalysisAddr(writeParam.addr)) {
		return 0;
	}
	
	assert(usInsParam.addr > 0);
	if (!this->_execInAnalysisAddr(usInsParam.addr)) {
		return 0;
	}
	
	asid_t target_asid = target_process_asid; // writes to memory space with this asid
	proccess_id_t target_pid = asid2pidIt->second;
	assert(this->mProcesses.find(target_pid) != this->mProcesses.end());
	PROCESS_DATA& target_process = this->mProcesses.find(target_pid)->second;

	proccess_id_t current_pid = execParam.pid; // the current execution process id

	assert(this->mProcesses.find(current_pid) != this->mProcesses.end());
	PROCESS_DATA& process_data = this->mProcesses.find(current_pid)->second;
	INS_PARAM insParam = this->_ins_param_with_db_check(process_data, usInsParam);
	
	uint32_t executing_layer = this->_getHighestLayer(process_data.shadowMemory, insParam.addr, insParam.size);
	
	PROCESS_LAYER& cpx_layer = process_data.layers[executing_layer];

	this->_add_instruction_to_layer(insParam, cpx_layer, process_data);
	PROCESS_EXECUTED_BYTE& x_layer = cpx_layer.executed[insParam.addr];

	assert(writeParam.size > 0);
	for (uint32_t i = 0; i < writeParam.size; ++i) {
		addr_t writeAddr = writeParam.addr + i;

		layer_t target_layer = executing_layer + 1; // default
		auto shb_it = target_process.shadowMemory.find(writeAddr);
		if (shb_it != target_process.shadowMemory.end()) {
			// check if the existing layer of target memory is higher
			SHADOW_BYTE& sb = shb_it->second;
			if (target_layer < sb.layerNumber) {
				target_layer = sb.layerNumber;
			}
		}

		// record writes from process
		TRIPLET(proccess_id_t, layer_t, addr_t) key = createAddrKey(target_pid, target_layer, writeAddr);
		x_layer.writeCounters[key] += 1;

		// record latest layer of shadow memory
		SHADOW_BYTE& tsb = target_process.shadowMemory[writeAddr];
		this->_update_shadow_byte_layer_number(writeAddr, tsb.layerNumber, target_layer, target_process);
		tsb.layerNumber = target_layer;
		

		// mark memory as written
		this->_markWritten(target_asid, writeAddr);
		
		// record memory location
		//x_layer.memLoc = this->_get_mem_location(target_asid, writeAddr, p);
	}

	return 0;

}

int AnalysisEngine::onBeforeWriteVirtAddr(const EXEC_ENV_PARAM& execParam, 
const INS_PARAM& insParam, const WRITE_PARAM& writeParam, void* p) 
{
	
	asid_t target_asid = execParam.asid;

	PROCESS_DATA& running_process = this->mProcesses.find(execParam.pid)->second;

	EXEC_ENV_PARAM current_env;
	current_env.pid = execParam.pid;
	current_env.tid = execParam.tid;
	current_env.asid = running_process.asid;

	return this->onBeforeWriteVirtAddr(target_asid, current_env, insParam, writeParam, p);

}

// only when debugging in PANDA!
//extern FILE* gOutputFile;

addr_t AnalysisEngine::_find_last_return_addr_in_module(void* cpu) {
	const int cmx = 10;

	addr_t callers[cmx];
	uint32_t n_caller;
	n_caller = this->mEnv.get_callers(callers, cmx, cpu);
	
	if (tracer::IsTrcActive(TRC_BIT_DEBUG)) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, " n_caller = %u [", n_caller);
		for (uint32_t i = 0; i < n_caller; ++i) {
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, " %08lx", callers[i]);
		}
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "]\n");
	}
	
	//bool called_from_module = false;
	addr_t module_caller = 0;
	
	for (uint32_t i = 0; i < n_caller; ++i) {
		if (this->_execInAnalysisAddr(callers[i])) {
			//called_from_module = true;
			module_caller = callers[i];
			// caller always contain the address of NEXT instruction
			// after CALL instruction.
			// thus, next instruction might have not been analyzed!
			break;
		}
	}
	
	//if (!called_from_module) {
	//	return 0;
	//}
	
	return module_caller;
	
}
	
addr_t AnalysisEngine::_find_last_function_caller_in_module(void* cpu) {
	const int cmx = 10;
	
	addr_t functions[cmx];
	uint32_t n_func;
	n_func = this->mEnv.get_functions(functions, cmx, cpu);
	
	if (tracer::IsTrcActive(TRC_BIT_DEBUG)) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, " n_func = %u [", n_func);
		for (uint32_t i = 0; i < n_func; ++i) {
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, " %08lx", functions[i]);
		}
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "]\n");
	}
	
	//bool called_from_module = false;
	addr_t module_caller = 0;
	
	for (uint32_t i = 0; i < n_func; ++i) {
		if (this->_execInAnalysisAddr(functions[i])) {
			//called_from_module = true;
			module_caller = functions[i];
			// functions return the start of function address that calls this syscall (directly / indirectly)
			// this is still an issue because the function is not the instruction that writes
			// to remote process, but this will have to do for now.
			break;
		}
	}
	
	//if (!called_from_module) {
	//	return 0;
	//}
	
	return module_caller;
	
}

bool AnalysisEngine::_fill_ins_param(INS_PARAM& out_ins_param, 
const EXEC_ENV_PARAM& current_process, uint64_t insn_start_addr, 
const PROCESS_DATA& process_data, void* p) {
	
	const auto insnInfoIt = process_data.insnInfos.find(insn_start_addr);
	const INSN_INFO* pInsnInfo = NULL;
	
	if (insnInfoIt != process_data.insnInfos.end()) {
		pInsnInfo = &(insnInfoIt->second);
		
	} else {
		assert("insnInfoIt != process_data.insnInfos.end()" && false);
		// if ins not found in insnInfos, add dummy, one-byte-size instruction
		// buffer 0xFF (marker)
		// This instr will be overwritten later when real insn is translated
		// For PROCESS_EXECUTED_BYTE, this should be fine because it just create new entry, if not exist.
		// and it does not contain any specific insn info anyway.
		// the specific info is kept in insnInfos map.
		
		// better not do this because it influenced the existing fow.
		// better add a new variable to contain this.
		// better, need to find the address of the call instruction!
		
		/*
		INSN_INFO insn_placeholder;
		insn_placeholder.addr = module_caller;
		insn_placeholder.size = 1;
		memcpy(insn_placeholder.buf, "\xFF", 1);
		process_data.insnInfos[module_caller] = insn_placeholder;
		
		pInsnInfo = &(process_data.insnInfos.find(module_caller)->second);
		*/
	}
	
	assert(pInsnInfo != NULL);
	
	out_ins_param.addr = pInsnInfo->addr;
	out_ins_param.size = pInsnInfo->size;
	out_ins_param.buf = pInsnInfo->buf;
	
	if (tracer::IsTrcActive(TRC_BIT_DEBUG)) {
		tracer::TrcTrace(p, TRC_BIT_DEBUG, " --- using ins: %lx %u:", 
			out_ins_param.addr, out_ins_param.size);
		for (uint32_t i = 0; i < out_ins_param.size; ++i) {
			tracer::TrcTrace(p, TRC_BIT_DEBUG, " %02x", out_ins_param.buf[i]);
		}
		tracer::TrcTrace(p, TRC_BIT_DEBUG, "\n");
	}

	return true;
	
}

bool AnalysisEngine::_create_ins_param_for_caller(INS_PARAM& out_ins_param, 
const EXEC_ENV_PARAM& current_process, void* p) 
{
	addr_t module_caller = this->_find_last_return_addr_in_module(p);
	if (module_caller == 0) {
		tracer::TrcTrace(p, TRC_BIT_WARN, "Function is not called from module, skipping");
		return false;
	}
	
	assert(this->mProcesses.find(current_process.pid) != this->mProcesses.end());
	PROCESS_DATA& process_data = this->mProcesses[current_process.pid];
	
	// last address of call instruction. Call insn is multibyte.
	addr_t call_insn_addr_last = module_caller - 1;
	const auto iheadIt = process_data.insnHead.find(call_insn_addr_last);
	if (iheadIt != process_data.insnHead.end()) {
		module_caller = iheadIt->second; // set the caller 
		
	} else {
		// if not exist in insnHead, just use the starting function address
		// as fallback.
		// if exist caller in current module, then, there should be functions as well
		// if not, it's really weird.
		module_caller = this->_find_last_function_caller_in_module(p);
		assert(module_caller > 0);
		
	}
	
	return this->_fill_ins_param(out_ins_param, current_process, module_caller, process_data, p);
}

bool AnalysisEngine::_create_ins_param_for_caller(INS_PARAM& out_ins_param, 
	const EXEC_ENV_PARAM& current_process, 
	uint64_t module_caller, void* p) 
{
	//
	assert(this->mProcesses.find(current_process.pid) != this->mProcesses.end());
	PROCESS_DATA& process_data = this->mProcesses[current_process.pid];
	
	// last address of call instruction. Call insn is multibyte.
	addr_t call_insn_addr_last = module_caller - 1;
	const auto iheadIt = process_data.insnHead.find(call_insn_addr_last);
	if (iheadIt != process_data.insnHead.end()) {
		module_caller = iheadIt->second; // set the caller 
		
	} else {
		tracer::TrcTrace(p, TRC_BIT_ERROR, "Unable to find insnHead for %lx, asid=%lx", 
				call_insn_addr_last, current_process.asid);
		assert("Unable to find insnHead address" && false);
	}
	
	return this->_fill_ins_param(out_ins_param, current_process, module_caller, process_data, p);
}


void AnalysisEngine::onBeforeApiMemoryWriteBulk(
asid_t target_process_asid, 
const EXEC_ENV_PARAM& current_process, 
const WRITE_PARAM& writeParam, 
void* p) 
{
	INS_PARAM ins_param;
	if (this->_create_ins_param_for_caller(ins_param, current_process, p)) {
		this->onBeforeWriteVirtAddr(target_process_asid, current_process, ins_param, writeParam, p);
	}
}

void AnalysisEngine::onBeforeApiMemoryWriteBulk(
asid_t target_process_asid, 
const EXEC_ENV_PARAM& current_process, 
const WRITE_PARAM& writeParam, 
uint64_t module_caller,
void* p) 
{
	INS_PARAM ins_param;
	if (this->_create_ins_param_for_caller(ins_param, current_process, module_caller, p)) {
		this->onBeforeWriteVirtAddr(target_process_asid, current_process, ins_param, writeParam, p);
	}
}


#define MERGE_MAP(added_to, added_map) \
	for (auto am_it = added_map.begin(); am_it != added_map.end(); ++am_it) { \
		added_to[am_it->first] += am_it->second; \
	}


void AnalysisEngine::_dump_transition_sources(addr_t current_addr, 
const transition_counter_map_t& transition_counter_map, FILE* out) const {
	for (auto it = transition_counter_map.begin(); it != transition_counter_map.end(); ++it) {
		const auto& key = it->first;
		uint32_t val = it->second;
		
		fprintf(out, "{\"pid\":%u,\"layer_no\":%u,\"from\":%lu,\"target\":%lu,\"total\":%u},\n",
				key.first, key.second.first, key.second.second, current_addr, val);
	}
}

void AnalysisEngine::_dump_write_counter(const write_counter_map_t& write_counter_map, 
FILE* out) const {
	for (auto it = write_counter_map.begin(); it != write_counter_map.end(); ++it) {
		const auto& key = it->first;
		uint32_t val = it->second;
		
		fprintf(out, "{\"pid\":%u,\"layer_no\":%u,\"addr\":%lu,\"total\":%u},\n",
				key.first, key.second.first, key.second.second, val);
	}
}

void AnalysisEngine::_dump_execution_logs(addr_t startExecAddr, addr_t lastExecAddr, 
const write_counter_map_t& writes_map, const PROCESS_LAYER& process_layer, FILE* out) const {
	
	for (addr_t xi = startExecAddr; xi <= lastExecAddr; ++xi) {
		auto it = process_layer.executed.find(xi);
		assert(it != process_layer.executed.end());
	}
	
	fprintf(out, "{\n");
	
	//fprintf(out, " >>> Execution <<<\n");
	fprintf(out, "\"execution\":{\"start_addr\":%lu,\"end_addr\":%lu,\"size\":%lu},\n",
			(uint64_t)startExecAddr, (uint64_t)lastExecAddr, 
			(uint64_t)lastExecAddr - startExecAddr + 1);
	
	//fprintf(out, "x %08lx -> %08lx %lx\n", 
	//		(uint64_t)startExecAddr, (uint64_t)lastExecAddr, 
	//		(uint64_t)lastExecAddr - startExecAddr + 1);
	
	//fprintf(out, " >>> Memory Location <<<\n");
	MEMLOC loc = MEMLOC_INIT;
	addr_t faddr = 0;
	for (addr_t xi = startExecAddr; xi <= lastExecAddr; ++xi) 
	{
		faddr = xi;
		const PROCESS_EXECUTED_BYTE& xb = process_layer.executed.find(xi)->second;
		if (xb.memLoc != MEMLOC_INIT) {
			if (xb.memLoc == MEMLOC_UNKNOWN) {
				loc = MEMLOC_UNKNOWN; // if unknown, try other bytes, but remember that UNKNOWN is set.
			} else {
				loc = xb.memLoc; // decisive location is found, break loop.
				break;
			}
		} else {
			// aspack 121, in address 004053ba, push 0 is changed to push <OEP> then RET.
			// the address 004053ba is not set.
			tracer::TrcTrace(TRC_BIT_WARN, "Unset memory location (%08lx) in layer %u",
					(uint64_t)xi, process_layer.layerNumber);
		}
	}
	const char * txt = mem_location_to_string(loc);
	tracer::TrcTrace(TRC_BIT_DEBUG, "%08lx: got loc=%d, txt=%s", faddr, loc, txt);
	fprintf(out, "\"memory_location\":\"%s\",\n", txt);
	//fprintf(out, "ml %s\n", mem_location_to_string(loc));
	
	uint32_t maxNumOfFrames = 0;
	for (addr_t xi = startExecAddr; xi <= lastExecAddr; ++xi) 
	{
		//const PROCESS_EXECUTED_BYTE& xb = process_layer.executed.find(xi)->second;
		auto info_it = process_layer.byte_info.find(xi);
		if (info_it != process_layer.byte_info.end()) {
			const PROCESS_BYTE_INFO& bi = info_it->second;
			uint32_t nFrames = bi.nFrames;
			maxNumOfFrames = nFrames > maxNumOfFrames ? nFrames : maxNumOfFrames;
		}
	}
	fprintf(out, "\"frames\":%u,\n", maxNumOfFrames);
	//fprintf(out, "f %u\n", maxNumOfFrames);

	//fprintf(out, " >>> Transition sources <<<\n");
	fprintf(out, "\"transitions_sources\":[\n");
	for (addr_t xi = startExecAddr; xi <= lastExecAddr; ++xi) {
		const PROCESS_EXECUTED_BYTE& xb = process_layer.executed.find(xi)->second;
		this->_dump_transition_sources(xi, xb.transitionCounters, out);
	}
	fprintf(out, "{}],\n");
	
	//fprintf(out, " >>> Program Points <<<\n");
	uint64_t ppBegin = ~0, ppEnd = 0;

	//std::set < uint64_t > setExecProgPoints;
	for (addr_t xi = startExecAddr; xi <= lastExecAddr; ++xi) {
		const PROCESS_EXECUTED_BYTE& xb = process_layer.executed.find(xi)->second;
		const PPRange& pprange = xb.pp_range;

		uint64_t ppMin = pprange.getBegin();
		ppBegin = ppMin < ppBegin ? ppMin : ppBegin;
		uint64_t ppMax = pprange.getEnd();
		ppEnd = ppMax > ppEnd ? ppMax : ppEnd;
	}
	fprintf(out, "\"program_points\":{\"start\":%lu,\"end\":%lu},\n",
			ppBegin, ppEnd);
	//fprintf(out, "pp %18lu -> %18lu\n", ppBegin, ppEnd);
	
	fprintf(out, "\"writes\":[\n");
	this->_dump_write_counter(writes_map, out);
	
	fprintf(out, "{}],\n");
	
	// TODO: dump the api call counters
	fprintf(out, "\"api_counter\":{\n");
	
	uint32_t uniq_api_calls = 0;
	uint32_t api_calls = 0;
	api_counter_map_t uniq_merged;
	
	for (addr_t xi = startExecAddr; xi <= lastExecAddr; ++xi) {
		auto it = process_layer.api_counter_byte.find(xi);
		if (it != process_layer.api_counter_byte.end()) {
			const PROCESS_API_CALL_COUNTER_BYTE& accb = it->second;
			assert(accb.addr == xi);
			MERGE_MAP(uniq_merged, accb.api_counter_map);
		}
	}
	uniq_api_calls = uniq_merged.size();
	for (auto umit = uniq_merged.begin(); umit != uniq_merged.end(); ++umit) {
		api_calls += umit->second;
	}
	
	fprintf(out, "\"api_count\":{\n");
	uint32_t ctr = 0;
	for (auto uit = uniq_merged.begin(); uit != uniq_merged.end(); ++uit) {
		fprintf(out, "\"0x%016lx\":%u", uit->first, uit->second);
		if (ctr < uniq_merged.size()-1) {
			fprintf(out, ",\n");
		}
		ctr++;
	}
	fprintf(out, "},\n"); // api_count
	
	fprintf(out, "\"uniq_api_calls\":%u,", uniq_api_calls);
	fprintf(out, "\"total_api_calls\":%u,", api_calls);
	fprintf(out, "\"group_count\":{\n");
	api_group_counter_map_t merged;
	
	for (addr_t xi = startExecAddr; xi <= lastExecAddr; ++xi) {
		auto it = process_layer.api_counter_byte.find(xi);
		if (it != process_layer.api_counter_byte.end()) {
			const PROCESS_API_CALL_COUNTER_BYTE& accb = it->second;
			MERGE_MAP(merged, accb.api_group_counter_map);
		}
	}
	
	int sz = merged.size();
	int szi = 0;
	for (auto mit = merged.begin(); mit != merged.end(); ++mit) {
		fprintf(out, "\"%s\":%u", 
				api_filter::api_group_to_string(mit->first), 
				mit->second);
		if (szi < sz-1) {
			fprintf(out, ",");
		}
		szi++;
	}
	
	fprintf(out, "}\n"); // group count
	
	fprintf(out, "}\n"); // api_counter
	
	fprintf(out, "}\n"); // execution
}

int AnalysisEngine::dumpLogs(FILE* out) const {
	assert(this->mInitialized);
	assert(out != NULL);
	
	// open object
	fprintf(out, "[\n");
	
	const std::map < proccess_id_t, PROCESS_DATA >& processes = this->mProcesses;
	for (auto processes_it = processes.begin(); processes_it != processes.end(); ++processes_it) {
		const PROCESS_DATA& process_data = processes_it->second;
		
		fprintf(out, "{\n");
		
		//fprintf(out, "===================== PROCESS pid=%u, asid=%016lx ========================\n",
		//	process_data.pid, process_data.asid);
		fprintf(out, "\"process\":{\"pid\":%u,\"asid\":%lu},\n", process_data.pid, process_data.asid);

		const std::map < layer_t, PROCESS_LAYER >& pd_layers = process_data.layers;
		uint32_t num_of_layers = pd_layers.size();
		//fprintf(out, "Number of Layers: %u\n", num_of_layers);
		fprintf(out, "\"num_layers\":%u,\n", num_of_layers);
		
		fprintf(out, "\"layers\":[\n");
		for (auto pdl_it = pd_layers.begin(); pdl_it != pd_layers.end(); ++pdl_it) {
			
			layer_t pd_layer_no = pdl_it->first;
			const PROCESS_LAYER& pd_layer = pdl_it->second;
			const std::map < addr_t, PROCESS_EXECUTED_BYTE >& executed_bytes = pd_layer.executed;

			if (executed_bytes.empty()) {
				// this case can occur on the writes performed by the deepest layer L.
				// those writes will be recorded at layer L+1, but since no bytes at that layer is executed,
				// the executed_bytes will be empty.
				continue;
			}
			
			fprintf(out, "{\n");
			//fprintf(out, " ==================== LAYER %u ====================\n", pd_layer_no);
			//fprintf(out, " ===== Executions =====\n");
			
			fprintf(out, "\"layer_no\":%u,\n", pd_layer_no);
			fprintf(out, "\"executions\":[\n");
			
			uint64_t startExecAddr = 0;
			uint64_t lastExecAddr = 0;
			write_counter_map_t consec_writes;
			
			for (auto xit = executed_bytes.begin(); xit != executed_bytes.end(); ++xit) {
				uint64_t currentExecAddr = xit->first;
				const PROCESS_EXECUTED_BYTE& procByte = xit->second;
				
				if (startExecAddr == 0) {
					startExecAddr = currentExecAddr;
					consec_writes.clear();
					
				} else {
					if (currentExecAddr != lastExecAddr + 1) {
						// dump execution log here
						_dump_execution_logs(startExecAddr, lastExecAddr, consec_writes, pd_layer, out);
						fprintf(out, ",");
						startExecAddr = currentExecAddr;
						consec_writes.clear();
					}
				}
				
				MERGE_MAP(consec_writes, procByte.writeCounters);
				lastExecAddr = currentExecAddr;
			}
			
			// dump last region of execution log
			_dump_execution_logs(startExecAddr, lastExecAddr, consec_writes, pd_layer, out);
			consec_writes.clear();
			fprintf(out, "]},\n");
			
		}

		fprintf(out, "{}],\n");
		fprintf(out, "\"last_executing_instructions\":[\n");
		//fprintf(out, " ==================== Last Executing Instructions ====================\n");

		const std::map < thread_id_t, PROCESS_LAST_INSTRUCTION >& last_insns = process_data.lastInstrs;
		for (auto lisn_it = last_insns.begin(); lisn_it != last_insns.end(); ++lisn_it) {
			thread_id_t tid = lisn_it->first;
			const PROCESS_LAST_INSTRUCTION& li = lisn_it->second;
			
			fprintf(out, "{\"thread\":%u,\"addr\":%lu,\"layer_no\":%u,\"insncnt\":%lu},\n",
					tid, li.addr, li.layer, li.insncnt);
			
			//fprintf(out, " Thread: %u, addr: %08lx, layer: %u, insncnt: %lu\n",
			//		tid, li.addr, li.layer, li.insncnt);
		}
		fprintf(out, "{}]},\n");
	}
	
	fprintf(out, "{}]\n");
	
	return 0;
}

// tested
void AnalysisEngine::_markWritten(asid_t asid, addr_t addr) {

	// don't set layer here, because it is determined by the layer number of executing code + 1.
	PROCESS_DATA& process_data = this->_asid2Process(asid);
	SHADOW_BYTE& sb = process_data.shadowMemory[addr];
	sb.nWritten += 1;
	sb.nfFlag = true;
	sb.memState = MEMSTATE_WRITTEN;

}

void AnalysisEngine::_update_shadow_byte_layer_number(
	addr_t addr, layer_t old_layer, layer_t new_layer, PROCESS_DATA& process_data) 
{
	// this can cause program to have layers without executing code at that layer.
	// addr_in_layer exists, but no executed bytes at that layer.

	// pretty confusing here
	// because can add new layers suddenly, even though it is empty and erased.

	{
		auto it = process_data.layers.find(old_layer);
		if (it != process_data.layers.end()) {
			it->second.addr_in_layer.erase(addr);
		}
	}

	//process_data.layers[old_layer].addr_in_layer.erase(addr);
	process_data.layers[new_layer].addr_in_layer.insert(addr);
}

INS_PARAM AnalysisEngine::_ins_param_with_db_check(
const PROCESS_DATA& process_data, 
const INS_PARAM& insParam) const {
	
	assert(insParam.addr != 0);
	
	auto insnInfoIt = process_data.insnInfos.find(insParam.addr);
	assert(insnInfoIt != process_data.insnInfos.end());
	
	const INSN_INFO& iinfo = insnInfoIt->second;
	assert(iinfo.addr == insParam.addr);
	
	INS_PARAM ins_tmp;
	
	ins_tmp.addr = insParam.addr;
	if (insParam.size == 0 || insParam.buf == NULL) {
		ins_tmp.size = iinfo.size;
		ins_tmp.buf = iinfo.buf;
		
	} else {
		ins_tmp.size = insParam.size;
		ins_tmp.buf = insParam.buf;
		
	}
	
	assert(ins_tmp.addr > 0);
	assert(ins_tmp.size > 0);
	assert(ins_tmp.buf != NULL);
	
	return ins_tmp;
	
}

void AnalysisEngine::_markExecuted(const EXEC_ENV_PARAM& execParam, const INS_PARAM& insParam, void* p) {

	//this->_markExecuted(execParam.asid, insParam.addr, insParam.size);
	//PROCESS_DATA& process_data = this->_asid2Process(execParam.asid);
	PROCESS_DATA& process_data = this->mProcesses[execParam.pid];
	
	INS_PARAM safeInsParam = this->_ins_param_with_db_check(process_data, insParam);
	
	uint32_t insn_size = safeInsParam.size;
	addr_t insn_addr = safeInsParam.addr;
	
	bool isNfBitSet = false;
	for (uint32_t i = 0; i < insn_size; ++i) {
		SHADOW_BYTE& sb = process_data.shadowMemory[insn_addr + i];
		if (sb.nfFlag) {
			isNfBitSet = true;
			break;
		}
	}
	
	layer_t executing_layer = this->_getHighestLayer(process_data.shadowMemory, insn_addr, insn_size);
	PROCESS_LAYER& process_layer = process_data.layers[executing_layer];
	process_layer.layerNumber = executing_layer;
	
	for (uint32_t i = 0; i < insn_size; ++i) {
		addr_t xaddr = insn_addr + i;
		SHADOW_BYTE& sb = process_data.shadowMemory[xaddr];
		this->_update_shadow_byte_layer_number(xaddr, sb.layerNumber, executing_layer, process_data);
		sb.layerNumber = executing_layer;
	}
	
	if (isNfBitSet) {
		// increase number of frames here for that layer
		// if nfFlag for all bytes in layer is reset, won't trigger next bytes.
		// thus, all consecutive bytes will have zero frame, while at least should have 1.

		auto& addr_in_layer = process_layer.addr_in_layer;
		for (auto mit = addr_in_layer.begin(); mit != addr_in_layer.end(); ++mit) {
			process_layer.byte_info[*mit].nFrames += 1;
		}
		
		for (auto mit = addr_in_layer.begin(); mit != addr_in_layer.end(); ++mit) {
			SHADOW_BYTE& ssb = process_data.shadowMemory[*mit];
			ssb.nfFlag = false;
			ssb.nWritten = 0;
		}
	}
	
	for (uint32_t i = 0; i < insn_size; ++i) {
		SHADOW_BYTE& sb = process_data.shadowMemory[insn_addr + i];
		sb.memState = MEMSTATE_EXECUTED;
	}

}

PROCESS_DATA& AnalysisEngine::_asid2Process(asid_t asid) {
	assert(this->mInitialized);
	auto it = this->mAsid2Pid.find(asid);
	if (it == this->mAsid2Pid.end()) {
		fprintf(stderr, "asid not found, asid=%lx\n", asid);
	}
	assert(it != this->mAsid2Pid.end());
	proccess_id_t pid = it->second;
	auto pit = this->mProcesses.find(pid);
	assert(pit != this->mProcesses.end());
	PROCESS_DATA& process_data = pit->second;
	return process_data;
}

MEMLOC AnalysisEngine::_get_mem_location(asid_t asid, addr_t addr, void* cpu) {
	
	const PROCESS_DATA& process_data = this->_asid2Process(asid);
	
	//uint64_t ebp = this->mEnv.read_stack_base(cpu);
	//uint64_t esp = this->mEnv.read_stack_pointer(cpu);
	
	uint64_t stack_base = this->mEnv.read_stack_base(cpu);
	uint64_t stack_limit = this->mEnv.read_stack_limit(cpu);
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "find location of addr=%08lx, base=%08lx, limit=%08lx", addr, stack_base, stack_limit);
	
	if (stack_base > 0 && stack_limit > 0 && addr <= stack_base && addr >= stack_limit) {
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, " --- STACK");
		return MEMLOC_STACK;
	}
	
	auto it = process_data.heapMemory.lower_bound(addr);
	if (it != process_data.heapMemory.end()) {
		const HEAP_MEMORY& memRange = it->second;
		if (memRange.startAddr <= addr && memRange.startAddr + memRange.length > addr) {
			return MEMLOC_HEAP;
		}
	}
	
	uint64_t imgBaseAddr = this->_findImageBaseAddr(cpu, addr);
	tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "find location of addr=%08lx, image base addr=%08lx", addr, imgBaseAddr);
	if (imgBaseAddr > 0) {
	
		panda::win::IMAGE_DOS_HEADER imageDosHeader;
		memset(&imageDosHeader, 0, sizeof(imageDosHeader));
		if (ENV_RET_S_ERR == this->mEnv.read(cpu, 
				(uint64_t)imgBaseAddr, 
				(uint8_t*)(&imageDosHeader), 
				sizeof(imageDosHeader))) 
		{
			return MEMLOC_UNKNOWN;
		}
		
		int peOffset = imageDosHeader.e_lfanew;
		panda::win::IMAGE_NT_HEADERS ntHeader;
		memset(&ntHeader, 0, sizeof(ntHeader));
		if (ENV_RET_S_ERR == this->mEnv.read(cpu, 
				(uint64_t)(imgBaseAddr + peOffset), 
				(uint8_t*)(&ntHeader), sizeof(ntHeader)))
		{
			return MEMLOC_UNKNOWN;
		}
		
		panda::win::DWORD dwImgSize = ntHeader.OptionalHeader.SizeOfImage;
		tracer::TrcTrace(cpu, TRC_BIT_DEBUG, "find location of addr=%08lx, image base addr=%08lx, sizeofimage=%08x", 
				addr, imgBaseAddr, dwImgSize);
		if (addr >= imgBaseAddr && addr < imgBaseAddr + dwImgSize) {
			tracer::TrcTrace(cpu, TRC_BIT_DEBUG, " --- MODULE");
			return MEMLOC_MODULE;
		}
	
	}
	
	if (addr >= 0x10000000) {
		return MEMLOC_LIB;
	}
	
	return MEMLOC_UNKNOWN;
	
}

void AnalysisEngine::onCreateHeap(const EXEC_ENV_PARAM& execParam, addr_t startAddr, uint32_t size, void* p) {
	this->onCreateHeapRemoteProcess(execParam, execParam.asid, startAddr, size, p);
}

void AnalysisEngine::onRemoveHeap(const EXEC_ENV_PARAM& execParam, addr_t startAddr, void* p) {
	this->onRemoveHeapRemoteProcess(execParam, execParam.asid, startAddr, p);
}

void AnalysisEngine::onCreateHeapRemoteProcess(const EXEC_ENV_PARAM& execParam, 
asid_t target_asid, addr_t startAddr, uint32_t size, void* p) {
	assert(this->mInitialized);
	PROCESS_DATA& process_data = this->_asid2Process(target_asid);
	
	auto heap_it = process_data.heapMemory.find(startAddr);
	if (heap_it != process_data.heapMemory.end()) {
		HEAP_MEMORY& h = heap_it->second;
		if (h.length < size) {
			h.length = size;
		}
		
	} else {
		HEAP_MEMORY h;
		h.length = size;
		h.startAddr = startAddr;
		process_data.heapMemory[startAddr] = h;
		
	}
}

void AnalysisEngine::onRemoveHeapRemoteProcess(const EXEC_ENV_PARAM& execParam, asid_t target_asid, addr_t startAddr, void* p) {
	assert(this->mInitialized);
	PROCESS_DATA& process_data = this->_asid2Process(target_asid);
	process_data.heapMemory.erase(startAddr);
}

addr_t AnalysisEngine::_findImageBaseAddr(void* env, addr_t startSearch) {
	
	uint64_t image_base = this->mEnv.read_image_base(env);
	if (image_base > 0) {
		return image_base;
	} else {
		return 0;
	}
	
	// use scandown bruteforce if reading from env somehow failed.
	/*
	addr_t start = startSearch & PAGE_MASK;
	
	// in volatility, the search is 5 MB. Since disk block size is 512 byte 
	// and memory block is 4KB
	// we try to multiply the search by 8.
	uint32_t searchMax = 40*1024*1024;
	for (uint32_t i=0; i < searchMax && start > i; i += 0x1000) {
		uint16_t word;
		if (ENV_RET_S_ERR == this->mEnv.read(env, start - i, (uint8_t*)&word, sizeof(word))) {
			continue;
		}

		// MZ signature ('ZM' for Little Endian)
		if (word == 0x5a4d) {
			//fprintf(debug_file, " - elapsed: %.6lf\n", t.end());
			return start - i;
		}
	}

	return 0;
	*/
}

void AnalysisEngine::onBeforeApiCall(const EXEC_ENV_PARAM& exec_param, const API_CALL_PARAM& api_call_param, void* p) {
	assert(this->mInitialized);
	PROCESS_DATA& process_data = this->_asid2Process(exec_param.asid);

	INS_PARAM caller_ins_param;
	if (!this->_create_ins_param_for_caller(caller_ins_param, exec_param, p)) {
		tracer::TrcTrace(p, TRC_BIT_WARN, "Unable to find caller from module for %s", api_call_param.api_name);
		return;
	}

	assert(caller_ins_param.addr > 0);
	assert(caller_ins_param.buf != NULL);
	assert(caller_ins_param.size > 0);

	layer_t layer_no = this->_getHighestLayer(process_data.shadowMemory, caller_ins_param.addr, caller_ins_param.size);

	PROCESS_LAYER& process_layer = process_data.layers.find(layer_no)->second;

	PROCESS_API_CALL_COUNTER_BYTE& api_counter = process_layer.api_counter_byte[caller_ins_param.addr];
	api_counter.addr = caller_ins_param.addr;
	
	api_filter::api_group api_group = api_filter::API_GROUP_OTHERS;
	if (api_call_param.api_name != NULL) {
		api_group = api_filter::classify_api(api_call_param.api_name);
	}
	
	api_counter.api_counter_map[api_call_param.api_va] += 1;
	api_counter.api_group_counter_map[api_group] += 1;

	//PAIR(thread_id_t, api_filter::api_group) tky;
	//tky.first = exec_param.tid;
	//tky.second = api_group;
	//api_counter.thread_api_group_counter_map[tky] += 1;
	
	//PAIR(thread_id_t, addr_t) uky;
	//uky.first = exec_param.tid;
	//uky.second = api_call_param.api_va;
	//api_counter.thread_api_counter_map[uky] += 1;

}

void AnalysisEngine::onAfterApiCall(const EXEC_ENV_PARAM& exec_param, const API_CALL_PARAM& api_call_param, void* p) {
	assert(this->mInitialized);
	// after api call does nothing.
	assert("Function AnalysisEngine::onAfterApiCall not implemented" && false);
}

#ifdef RUNTEST
const std::map < asid_t, proccess_id_t >& AnalysisEngine::getAsid2Pid() const {
	return this->mAsid2Pid;
}
const std::map < proccess_id_t, PROCESS_DATA >& AnalysisEngine::getProcesses() const {
	return this->mProcesses;
}
layer_t AnalysisEngine::_getHighestLayerProxy(const std::map < addr_t, 
SHADOW_BYTE >& shadowMemory, addr_t addr, uint32_t size) const {
	return this->_getHighestLayer(shadowMemory, addr, size);
}
void AnalysisEngine::_markWrittenProxy(asid_t asid, addr_t addr) {
	this->_markWritten(asid, addr);
}
void AnalysisEngine::_markExecutedProxy(const EXEC_ENV_PARAM& execParam, 
const INS_PARAM& insParam, void* p) {
	this->_markExecuted(execParam, insParam, p);
}
const PROCESS_LAST_INSTRUCTION& AnalysisEngine::_get_global_last_instruction() const {
	return this->mGlobalLastInsn;
}
#endif
