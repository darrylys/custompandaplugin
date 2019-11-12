#ifndef ANALYSIS_ENGINE_H
#define ANALYSIS_ENGINE_H

#include "pp_range.h"
#include "api_filter.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <map>
#include <string>
#include <set>

/**
Deletes all vector with pointer contents.
vector<obj*> val;

don't use this for vector with non-pointer contents.

and clears the contents automatically
*/
#define DELETE_VECTOR(vectorObj)										 \
	for (auto it = (vectorObj).begin(); it != (vectorObj).end(); ++it) { \
		delete *it;														 \
	}																	 \
	vectorObj.clear();

/**
Deletes maps with pointer values
map<key, val*> obj.

key is untouched.

and clears the contents automatically
*/
#define DELETE_MAP(mapObj)												\
	for (auto it = (mapObj).begin(); it != (mapObj).end(); ++it) {		\
		delete it->second;												\
	}																	\
	mapObj.clear();
	
#define PAGE_MASK (0xFFFFFFFFFFFFF000LL)
#define KERNEL_START_ADDR (0x80000000LL)

typedef uint32_t thread_id_t;
typedef uint64_t asid_t;
typedef uint32_t proccess_id_t;
typedef uint32_t layer_t;
typedef uint64_t addr_t;
typedef uint64_t guest_insncnt_t;

enum ENV_RET {
	ENV_RET_S_OK,
	ENV_RET_S_ERR
};

#define DEFAULT_CSV_SEPARATOR (',')

typedef struct _PROGRAM_POINT {
	addr_t caller;
	addr_t pc;
	addr_t cr3;
#ifdef __cplusplus
    bool operator <(const _PROGRAM_POINT &p) const {
        return (this->pc < p.pc) || \
               (this->pc == p.pc && this->caller < p.caller) || \
               (this->pc == p.pc && this->caller == p.caller && this->cr3 < p.cr3);
    }
    bool operator ==(const _PROGRAM_POINT &p) const {
        return (this->pc == p.pc && this->caller == p.caller && this->cr3 == p.cr3);
    }
#endif
} PROGRAM_POINT;

// implement in panda
/**
Interface to read stuff from environment from the AnalysisEngine
Implement this interface to allow connecting the analysis engine with its environment
*/
class IEnvironment {
public:
	IEnvironment();
	virtual ~IEnvironment();

	/**
	Read byte from environment.
	@param env whatever object. For Panda / QEMU, pass CPUState* here
	@param addr virtual address of buffer to read in guest
	@param outBuf out buffer to place copied data from guest
	@param outLen the length of out buffer
	@return OK if success, ERR otherwise
	*/
	virtual ENV_RET read(void* env, addr_t addr, uint8_t* outBuf, int outLen) = 0;
	
	/**
	Read EBP register (x86) or equivalent in other architectures
	*/
	virtual uint64_t read_stack_base(void* env) = 0;
	
	/**
	Read ESP register (x86) or equivalent in other architectures
	*/
	virtual uint64_t read_stack_pointer(void* env) = 0;
	
	/**
	 * @brief Read the stack limit from environment
	 * @param env
	 * @return 
	 */
	virtual uint64_t read_stack_limit(void* env) = 0;
	
	/**
	 * @brief read the image base from memory
	 * @param env
	 * @return 
	 */
	virtual uint64_t read_image_base(void * env) = 0;
	
	/**
	Read guest instruction count, the number of guest instructions executed before current guest instruction
	globally.
	*/
	virtual uint64_t read_guest_insnctr(void* env) = 0;

	/**
	Reads functions that are called up to this point
	@param fn_out the output buffer
	@param n_fn the number of functions to find, should be length of output buffer
	@param env QEMU CPU* pointer
	@returns number of functions inside fn_out, always <= n_fn
	*/
	virtual uint32_t get_functions(addr_t fn_out[], uint32_t n_fn, void* env) = 0;

	/**
	Reads the callers that are called up to this point
	param cl_out the output buffer
	@param n_cl the number of functions to find, should be length of output buffer
	@param env QEMU CPU* pointer
	@returns number of functions inside fn_out, always <= n_cl
	*/
	virtual uint32_t get_callers(addr_t cl_out[], uint32_t n_cl, void* env) = 0;
	
	/**
	obtains a program point (triplet of (asid, pc, cr3))
	@see callstack_instr plugin for details.
	@see callstack_instr_int_fns.h for function prototype
	@return true if success, false otherwise
	*/
	virtual bool get_program_point(void* env, PROGRAM_POINT& out) = 0;
};

typedef struct _ANALYSIS_PARAM {
	const char * asidCsv;
	const char * pidCsv;

	// must be accessible throughout AnalysisEngine operations
	IEnvironment* pEnv;

	addr_t startAnalysisAddr;
	addr_t endAnalysisAddr;
	
	char csv_separator;

	// default values
	_ANALYSIS_PARAM() 
		: asidCsv(NULL),
		pidCsv(NULL),
		pEnv(NULL),
		startAnalysisAddr(0x0),
		endAnalysisAddr(0x10000000),
		csv_separator(DEFAULT_CSV_SEPARATOR)
	{
	}
} ANALYSIS_PARAM;

// current execution context
typedef struct _EXEC_ENV_PARAM {
	asid_t asid;
	proccess_id_t pid;
	thread_id_t tid;

	_EXEC_ENV_PARAM() 
		:asid(0),
		pid(0),
		tid(0)
	{
	}

} EXEC_ENV_PARAM;

typedef struct _INS_PARAM {
	const uint8_t* buf;
	addr_t addr;
	uint32_t size;

	_INS_PARAM()
		: buf(NULL),
		addr(0),
		size(0)
	{
	}

} INS_PARAM;

typedef struct _WRITE_PARAM {
	const uint8_t* buf;
	addr_t addr;
	uint32_t size;

	_WRITE_PARAM() 
		: buf(NULL),
		addr(0),
		size(0)
	{}

} WRITE_PARAM;

typedef struct _API_CALL_PARAM {
	const char * api_name;
	addr_t api_va;
	
	_API_CALL_PARAM()
		: api_name(NULL),
		api_va(0)
	{}

} API_CALL_PARAM;

// the last instruction of a thread executed so far
typedef struct _PROCESS_LAST_INSTRUCTION {
	addr_t addr;
	asid_t owner_asid;
	layer_t layer;
	uint32_t size;
	proccess_id_t owner_pid;
	guest_insncnt_t insncnt;
	//uint8_t buf[16];
    
	_PROCESS_LAST_INSTRUCTION() 
	: addr(0),
	owner_asid(0),
	layer(0),
	size(0),
	owner_pid(0),
	insncnt(0)
	{ }
} PROCESS_LAST_INSTRUCTION;

enum MEMSTATE {
	MEMSTATE_UNKNOWN = 101,
	MEMSTATE_WRITTEN = 102,
	MEMSTATE_EXECUTED = 103,
	MEMSTATE_UNPACKED = 104,
	MEMSTATE_REPACKED = 105
};

enum MEMLOC {
	MEMLOC_INIT = 201,
	MEMLOC_UNKNOWN = 202,
	MEMLOC_MODULE = 203,
	MEMLOC_STACK = 204,
	MEMLOC_HEAP = 205,
	MEMLOC_LIB = 206
};

typedef struct _SHADOW_BYTE {
	MEMSTATE memState;
	bool nfFlag;
	layer_t layerNumber;
	uint32_t nWritten;

	_SHADOW_BYTE() 
		: memState(MEMSTATE_UNKNOWN),
		nfFlag(false),
		layerNumber(0),
		nWritten(0)
	{
	}
} SHADOW_BYTE;

#define PAIR(t1, t2) std::pair < t1, t2 >
#define TRIPLET(t1, t2, t3) std::pair < t1, std::pair < t2, t3 > >
typedef TRIPLET(proccess_id_t, layer_t, addr_t) AddrKey;
typedef PAIR(thread_id_t, api_filter::api_group) ThreadApiCounterKey;

TRIPLET(proccess_id_t, layer_t, addr_t) createAddrKey(proccess_id_t pid, layer_t layer_num, addr_t addr);

typedef struct _PROCESS_BYTE_INFO {
	uint32_t nFrames;

	_PROCESS_BYTE_INFO()
		: nFrames(0)
	{}

} PROCESS_BYTE_INFO;

typedef std::map < TRIPLET(proccess_id_t, layer_t, addr_t), uint32_t > write_counter_map_t;
typedef std::map < TRIPLET(proccess_id_t, layer_t, addr_t), uint32_t > transition_counter_map_t;
typedef std::map < addr_t, uint32_t > api_counter_map_t;
typedef std::map < api_filter::api_group, uint32_t > api_group_counter_map_t;

// this is not combined with PROCESS_EXECUTED_BYTE because compared to writes and transitions,
// api counter is significantly less, and thus, might contain empty maps all over the place.
// and it is a waste of memory. Most instructions won't call APIs.
typedef struct _PROCESS_API_CALL_COUNTER_BYTE {

	addr_t addr;
	
	// counts the number of calls of each api_group
	//thread_api_group_counter_map_t thread_api_group_counter_map;
	
	// counts the number of calls of each api, not grouped.
	//thread_api_counter_map_t thread_api_counter_map;
	
	// stores the number of calls done for each api, regardless of threads
	api_counter_map_t api_counter_map;
	
	// stores number of calls done per group.
	api_group_counter_map_t api_group_counter_map;

	_PROCESS_API_CALL_COUNTER_BYTE()
		: addr(0)
	{}

} PROCESS_API_CALL_COUNTER_BYTE;

typedef struct _PROCESS_EXECUTED_BYTE {

	// address of this byte
	addr_t addr;

	PPRange pp_range;

	// no nFrames here because most written addresses are not to be executed.

	// the number of times this instruction writes somewhere
	write_counter_map_t writeCounters;

	// the counter for the number of addresses that jumps to this instruction
	// combines all transitions from multiple threads here, if any.
	transition_counter_map_t transitionCounters;

	// location of this address (heap / stack / module / etc.)
	MEMLOC memLoc;

	_PROCESS_EXECUTED_BYTE() 
		: addr(0),
		pp_range(),
		writeCounters(),
		transitionCounters(),
		memLoc(MEMLOC_INIT)
	{ }
} PROCESS_EXECUTED_BYTE;

typedef struct _PROCESS_LAYER {
	layer_t layerNumber;
	std::map < addr_t, PROCESS_EXECUTED_BYTE > executed;
	std::map < addr_t, PROCESS_BYTE_INFO > byte_info;
	std::map < addr_t, PROCESS_API_CALL_COUNTER_BYTE > api_counter_byte;
	
	// set of addresses in this layer, at latest time.
	// other maps include historical addresses data. This map only puts the latest data.
	// thus, all addresses in this map are not found in any other layer, at all times.
	// if a byte layer number is changed, it is erased in old layer, and added in new layer.
	std::set < addr_t > addr_in_layer;

	_PROCESS_LAYER() 
		: layerNumber(0)
	{}

} PROCESS_LAYER;

typedef struct _HEAP_MEMORY {
	addr_t startAddr;
	uint32_t length;

	_HEAP_MEMORY() 
		: startAddr(0),
		length(0)
	{}

} HEAP_MEMORY;

typedef struct _INSN_INFO {
	addr_t addr;
	uint32_t size;
	uint8_t buf[20];

	_INSN_INFO()
		: addr(0),
		size(0)
	{
		memset(buf, 0, sizeof(buf));
	}

} INSN_INFO;

typedef struct _PROCESS_DATA {
	proccess_id_t pid;
	asid_t asid;
	std::map < thread_id_t, PROCESS_LAST_INSTRUCTION > lastInstrs;
	std::map < layer_t, PROCESS_LAYER > layers;
	std::map < addr_t, SHADOW_BYTE > shadowMemory;
	std::map < addr_t, HEAP_MEMORY > heapMemory;
	std::map < addr_t, INSN_INFO > insnInfos;
	
	// stores the address of the start of instruction.
	// for multibyte instructions
	std::map < addr_t, addr_t > insnHead;

	_PROCESS_DATA() 
		: pid(0),
		asid(0)
	{ }

} PROCESS_DATA;

// tested
bool parseCsv(const char * csv, char separator, std::vector < std::string >& out);
bool isHex(const char * str);
bool isDec(const char * str);

const char * mem_location_to_string(MEMLOC mem_loc);

/**
 * @class AnalysisEngine
 * @author darryl
 * @date 02/03/19
 * @file AnalysisEngine.h
 * @brief This class is not thread safe. Be careful if multithreading
 */
class AnalysisEngine {
public:
	AnalysisEngine(const ANALYSIS_PARAM& param);
	~AnalysisEngine();
	
	/**
	 * @brief Initializes the engine. Call this once before doing everything else
	 * @return true if success, false if failed
	 */
	bool init();
	
	/**
	 * @brief call this function before translating every instruction 
	 * @param execParam must contain all entries, asid, pid, and thread id
 	 * @param insParam must contain all entries, size, addr and buf
	 * @param p
	 * @return 1 if instruction is to be analyzed (which calls onBeforeInsnExec), 0 otherwise
	 */
	int onBeforeInsnTranslate(const EXEC_ENV_PARAM& execParam, 
			const INS_PARAM& insParam, void* p);
	
	/**
	 * @brief call this function before executing every instruction that is marked for
	 * analysis by returning 1 from onBeforeInsnTranslate
	 * @param execParam current executing context. must contain all entries, asid, pid, and thread id
	 * @param insParam must contain addr. size and/or buf may be 0 and NULL respectively.
	 * @param p
	 * @see onBeforeInsnTranslate
	 * @return always 0
	 */
	int onBeforeInsnExec(const EXEC_ENV_PARAM& execParam, 
			const INS_PARAM& insParam, void* p);

	/**
	 * @brief call this function after translating every instruction
	 * Currently not supported. Calling this function simply logs error and exits.
	 * @param execParam
	 * @param insParam
	 * @param p
	 * @return 1 if instruction is to be analyzed after execution, 0 otherwise
	 */
	int onAfterInsnTranslate(const EXEC_ENV_PARAM& execParam, 
			const INS_PARAM& insParam, void* p);

	/**
	 * @brief call this function after executing every instruction
	 * currently not supported. Calling this function simply logs error and exits.
	 * @param execParam
	 * @param insParam
	 * @param p
	 * @return 
	 */
	int onAfterInsnExec(const EXEC_ENV_PARAM& execParam, 
			const INS_PARAM& insParam, void* p);

	
	/**
	 * @Deprecated
	 * @brief old version of before_virt write callback.
	 * @param execParam The asid is the target process, pid and tid is the current process. This is confusing.
	 * Thus, the new version is created, and this one is depreated
	 * @param insParam must contain addr, others may be 0 or NULL
	 * @param writeParam all must be filled.
	 * @param p
	 * @return always 0
	 */
	int onBeforeWriteVirtAddr(const EXEC_ENV_PARAM& execParam, const INS_PARAM& insParam, 
		const WRITE_PARAM& writeParam, void* p);

	/**
	 * @brief new version of onBeforeWriteVirtAddr
	 * @param target_process_asid the asid of process where the bytes are written to.
	 * @param execParam current asid, pid and tid that is executing current instruction
	 * @param insParam must contain addr. others might be zeroed out
	 * @param writeParam
	 * @param p
	 * @return 
	 */
	int onBeforeWriteVirtAddr(asid_t target_process_asid, const EXEC_ENV_PARAM& execParam, const INS_PARAM& insParam, 
		const WRITE_PARAM& writeParam, void* p);

	/**
	 * @brief call this function before calling system call NtWriteVirtualMemory or any other
	 * bulk API write such as memset / memcpy / WriteProcessMemory. Since the analysis engine does
	 * not process all executing address, this function can be used to handle writes performed by
	 * API functions correctly. If a code at layer L calls API to write stuff somewhere, 
	 * it makes more sense to label the memory written by the API in layer L+1.
	 * 
	 * @param target_process_asid asid of target process, might be current process.
	 * @param current_process asid, pid and tid of currently running instruction
	 * @param writeParam put the buffer contents here (addr, size, buf)
	 * @param p
	 */
	void onBeforeApiMemoryWriteBulk(asid_t target_process_asid, 
		const EXEC_ENV_PARAM& current_process, const WRITE_PARAM& writeParam, void* p);
		
	/**
	 * @brief Same as onBeforeApiMemoryWriteBulk without ins_param. The difference is that this function
	 * allows for passing the ins_param directly, instead of generated by function.
	 * 
	 * @param target_process_asid
	 * @param current_process
	 * @param writeParam
	 * @param module_caller
	 * @param p
	 */
	void onBeforeApiMemoryWriteBulk(asid_t target_process_asid, 
		const EXEC_ENV_PARAM& current_process, const WRITE_PARAM& writeParam, uint64_t module_caller, 
		void* p);

	/**
	 * @brief Call this function to add dynamic memory regions in current process. If 
	 * startAddr exists, it updates the existing data if given size is larger than existing.
	 * @param execParam asid, pid and tid of currently running instruction
	 * @param startAddr
	 * @param size
	 * @param p
	 */
	void onCreateHeap(const EXEC_ENV_PARAM& execParam, addr_t startAddr, uint32_t size, void* p);
	
	/**
	 * @brief Create heap in remote process.
	 * @param execParam
	 * @param target_asid
	 * @param startAddr
	 * @param size
	 * @param p
	 */
	void onCreateHeapRemoteProcess(const EXEC_ENV_PARAM& execParam, asid_t target_asid, addr_t startAddr, uint32_t size, void* p);
	
	/**
	 * @brief call this function to remove the dynamic memory region
	 * @param execParam
	 * @param startAddr
	 * @param p
	 */
	void onRemoveHeap(const EXEC_ENV_PARAM& execParam, addr_t startAddr, void* p);
	
	/**
	 * @brief Removes heap in remote process
	 * @param execParam
	 * @param target_asid
	 * @param startAddr
	 * @param p
	 */
	void onRemoveHeapRemoteProcess(const EXEC_ENV_PARAM& execParam, asid_t target_asid, addr_t startAddr, void* p);
	
	/**
	 * @brief call this function before api call performed
	 * @param exec_param, pid and tid of currently running instruction
	 * @param api_call_param, api call parameter
	 * @param p
	 */
	void onBeforeApiCall(const EXEC_ENV_PARAM& exec_param, const API_CALL_PARAM& api_call_param, void* p);

	/**
	 * @brief call this function after api call completes
	 * @param exec_param, pid and tid of currently running instruction
	 * @param api_call_param, api call parameter
	 * @param p
	 */
	void onAfterApiCall(const EXEC_ENV_PARAM& exec_param, const API_CALL_PARAM& api_call_param, void* p);

	/**
	 * @brief Dump the analysis data to specified file descriptor
	 * @param out the file to dump the analysis data
	 * @return always 0
	 */
	int dumpLogs(FILE* out) const;
	
	/**
	 * @brief checks (start address <= addr < end address)
	 * @param addr
	 * @return 
	 */
	bool isInAnalysisSpace(addr_t addr) const;
	
	/**
	 * @brief checks whether analysis is conducted on given process id
	 * @param pid
	 * @return 
	 */
	bool isAnalyzePid(proccess_id_t pid) const;
	
	/**
	 * @brief checks whether analysis is conducted on given asid / cr3
	 * @param asid
	 * @return 
	 */
	bool isAnalyzeAsid(asid_t asid) const;
	
	/**
	 * @brief checks whether addr < 0x80000000 (kernel address space)
	 * @param addr
	 * @return 
	 */
	bool isInUserAddrSpace(addr_t addr) const;

#ifdef RUNTEST
	const std::map < asid_t, proccess_id_t >& getAsid2Pid() const;
	const std::map < proccess_id_t, PROCESS_DATA >& getProcesses() const;
	layer_t _getHighestLayerProxy(const std::map < addr_t, SHADOW_BYTE >& shadowMemory, addr_t addr, uint32_t size) const;
	void _markWrittenProxy(asid_t asid, addr_t addr);
	void _markExecutedProxy(const EXEC_ENV_PARAM& execParam, const INS_PARAM& insParam, void* p);
	const PROCESS_LAST_INSTRUCTION& _get_global_last_instruction() const;
#endif

private:
	std::string mStrPidCsv;
	std::string mStrAsidHexCsv;
	IEnvironment& mEnv;
	bool mInitialized;
	std::map < asid_t, proccess_id_t > mAsid2Pid;
	std::map < proccess_id_t, PROCESS_DATA > mProcesses;
	addr_t mStartAnalysisAddr;
	addr_t mEndAnalysisAddr;

	// the very last instruction executed, threads, processes and all.
	PROCESS_LAST_INSTRUCTION mGlobalLastInsn;
	
	// flag whether global last insn has been set previously or not.
	bool mGlobalLastInsnIsSet;
	
	// csv separator used for pid csv and asid hex csv
	char mCsvSeparator;
	
	/**
	 * Might be useful to also provide separator charater as parameter.
	 * @brief Parses asid hex csv and pid decimal csv of the processes to be analyzed
	 * @param hexAsidCsv csv of asid in hex, separator is semicolon (;) because panda config already
	 * uses comma (,) character
	 * @param pidDecCsv
	 * @return 
	 */
	bool _readConfig(const char * hexAsidCsv, const char * pidDecCsv);
	
	/**
	 * @brief just proxy to isInAnalysisSpace
	 * @param addr
	 * @return
	 * @see isInAnalysisSpace
	 */
	bool _execInAnalysisAddr(addr_t addr) const;
	
	/**
	 * @brief just proxy to isInAnalysisSpace
	 * @param addr
	 * @return 
	 * @see isInAnalysisSpace
	 */
	bool _writeInAnalysisAddr(addr_t addr) const;
	
	/**
	 * @brief obtains the highest layer of all bytes from addr to addr + size - 1.
	 * This is useful to find the layer number of an instruction. An instruction
	 * can have arbitrary number of bytes. Any modifications of these bytes means
	 * entire instruction has been changed. Thus, an instructions' layer is determined
	 * by the highest layer number of its individual bytes.
	 * 
	 * @param shadowMemory
	 * @param addr
	 * @param size
	 * @return layer number
	 */
	layer_t _getHighestLayer(const std::map < addr_t, SHADOW_BYTE >& shadowMemory, 
			addr_t addr, uint32_t size) const;
	
	/**
	 * @brief marks current byte as "executed"
	 * @param execParam must be all filled
	 * @param insParam addr must be filled. src and buf might be 0 and/or NULL respectively
	 * @param p
	 */
	void _markExecuted(const EXEC_ENV_PARAM& execParam, const INS_PARAM& insParam, void* p);
	
	/**
	 * @brief marks given addr in given asid as "written"
	 * @param asid
	 * @param addr
	 */
	void _markWritten(asid_t asid, addr_t addr);
	
	/**
	 * @brief Updates existing global last instruction.
	 * @param last new latest instruction executed by process
	 */
	void _updateGLobalLastInsn(const PROCESS_LAST_INSTRUCTION& last);
	
	/**
	 * @brief Get memory location of given address in specified asid
	 * @param asid
	 * @param addr
	 * @param cpu
	 * @return 
	 */
	MEMLOC _get_mem_location(asid_t asid, addr_t addr, void * cpu);
	
	/**
	 * @brief find image base address by using scandown technique.
	 * The search size is 40MB max. The rationale is since Volatility searches for 5 MB
	 * in disk and disk has 512 byte blocks and memory is 4KB blocks, multiply the
	 * search size by 8.
	 * 
	 * @param env
	 * @param startSearch
	 * @return address of 'MZ' header in memory, 0 if not found
	 */
	addr_t _findImageBaseAddr(void *env, addr_t startSearch);
	
	/**
	 * @brief finds the process data of specified asid.
	 * @param asid
	 * @return 
	 */
	PROCESS_DATA& _asid2Process(asid_t asid);
	
	/**
	 * @brief call this function before modifying the layer number of a shadow byte.
	 * @param addr the address of shadow byte
	 * @param old_layer
	 * @param new_layer
	 * @param process_data
	 */
	void _update_shadow_byte_layer_number(addr_t addr, layer_t old_layer, 
	layer_t new_layer, PROCESS_DATA& process_data);
	
	/**
	 * @brief 
	 * @param startExecAddr
	 * @param lastExecAddr
	 * @param writes_map
	 * @param process_layer
	 * @param out
	 */
	void _dump_execution_logs(addr_t startExecAddr, addr_t lastExecAddr, 
		const write_counter_map_t& writes_map, const PROCESS_LAYER& process_layer, 
		FILE* out) const;
	
	/**
	 * @brief dumps the transitions to supplied current address to supplied file
	 * @param current_addr
	 * @param transition_counter_map
	 * @param out
	 */
	void _dump_transition_sources(addr_t current_addr, const transition_counter_map_t& 
		transition_counter_map, FILE* out) const;
	
	/**
	 * @brief dumps the writes counter map to supplied file
	 * @param write_counter_map
	 * @param out
	 */
	void _dump_write_counter(const write_counter_map_t& write_counter_map, FILE* out) const;
	
	/**
	 * @brief Adds instruction to layer, if not already exist.
	 * @param insParam addr, size and buf must be all set!
	 * @param current_layer
	 * @param current_process
	 */
	void _add_instruction_to_layer(const INS_PARAM& insParam, 
			PROCESS_LAYER& current_layer, PROCESS_DATA& current_process);
	
	/**
	 * @brief Creates a new insparam that combines data from INSN_INFO structure.
	 * if insParam is fully filled, the addr, the size and the 
	 * buf are all OK, its copy is returned.
	 * 
	 * if insParam only has its addr filled, this function will 
	 * return the INS_PARAM with other details filled.
	 * with existing data
	 * 
	 * @param process_data
	 * @param insParam
	 * @return 
	 */
	INS_PARAM _ins_param_with_db_check(const PROCESS_DATA& process_data, 
			const INS_PARAM& insParam) const;
			
	/**
	 * @brief Finds last return address of an API call that is performed in
	 * executable module. If the API is not called from module, this returns 0
	 * 
	 * @param cpu
	 * @return 0 if failed
	 */
	addr_t _find_last_return_addr_in_module(void* cpu);
	
	/**
	 * @brief Finds the address of the function that calls an API in module
	 * @param cpu
	 * @return 0 if failed
	 */
	addr_t _find_last_function_caller_in_module(void* cpu);

	/**
	 * @brief finds the caller within the analysis module range that does this API / system call.
	 * @param
	 * @param
	 * @param
	 * @return true if success, false otherwise
	 */
	bool _create_ins_param_for_caller(INS_PARAM& out_ins_param, const EXEC_ENV_PARAM& current_process, void* p);
	
	/**
	 * @brief same as above, but with added module_caller to pass.
	 * @param out_ins_param
	 * @param current_process
	 * @param module_caller
	 * @param p
	 * @return 
	 */
	bool _create_ins_param_for_caller(INS_PARAM& out_ins_param, const EXEC_ENV_PARAM& current_process, 
	uint64_t module_caller, void* p);
	
	/**
	 * @brief 
	 * @param out_ins_param
	 * @param current_process
	 * @param insn_start_addr
	 * @param p
	 * @return 
	 */
	bool _fill_ins_param(INS_PARAM& out_ins_param, const EXEC_ENV_PARAM& current_process, 
	uint64_t insn_start_addr, const PROCESS_DATA& process_data, void* p);

};

#endif