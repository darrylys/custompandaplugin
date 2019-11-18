#include "AnalysisEngine.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <vector>
#include <map>

#include "Tracer.h"

#ifdef RUNTEST
#define DUMMY_INSTR			(reinterpret_cast < const uint8_t* > ("\x90\x90\x90\x90\x90\x90"))
#define DUMMY_INSTR_SIZE	(6)
#define DUMMY_WRITE			(reinterpret_cast < const uint8_t* > ("\x7a\x7a\x7a\x7a\x7a\x7a"))
#define DUMMY_WRITE_SIZE	(6)

class DummyEnv : public IEnvironment {
public:
	DummyEnv() 
		:instrcnt(0)
	{
	}

	~DummyEnv() {
	}

	ENV_RET read(void* env, addr_t addr, uint8_t* outBuf, int outLen) {
		return ENV_RET_S_OK;
	}

	uint64_t read_stack_base(void* env) {
		return 0;
	}

	uint64_t read_stack_pointer(void* env) {
		return 0;
	}

	uint64_t read_stack_limit(void* env) {
		return 0;
	}

	uint64_t read_image_base(void * env) {
		return 0;
	}

	uint64_t read_guest_insnctr(void* env) {
		return ++instrcnt;
	}

	uint32_t get_functions(addr_t fn_out[], uint32_t n_fn, void* env) {
		return 0;
	}

	uint32_t get_callers(addr_t cl_out[], uint32_t n_cl, void* env) {
		return 0;
	}
	
	bool get_program_point(void* env, PROGRAM_POINT& out) {
		PROGRAM_POINT p = {0};
		out = p;
		return true;
	}

private:
	uint64_t instrcnt;
};

class DummyEnvWithCaller : public IEnvironment {
public:
	DummyEnvWithCaller(const addr_t* clin, int clin_len) 
		:instrcnt(0)
	{
		for (int i=0; i<clin_len; ++i) {
			this->callers.push_back(clin[i]);
		}

	}

	~DummyEnvWithCaller() {
	}

	ENV_RET read(void* env, addr_t addr, uint8_t* outBuf, int outLen) {
		return ENV_RET_S_OK;
	}

	uint64_t read_stack_base(void* env) {
		return 0;
	}

	uint64_t read_stack_pointer(void* env) {
		return 0;
	}

	uint64_t read_stack_limit(void* env) {
		return 0;
	}

	uint64_t read_image_base(void * env) {
		return 0;
	}

	uint64_t read_guest_insnctr(void* env) {
		return ++instrcnt;
	}

	uint32_t get_functions(addr_t fn_out[], uint32_t n_fn, void* env) {
		return 0;
	}

	uint32_t get_callers(addr_t cl_out[], uint32_t n_cl, void* env) {
		for (int i=0; i<callers.size(); ++i) {
			cl_out[i] = callers[i];
		}
		return callers.size();
	}
	
	bool get_program_point(void* env, PROGRAM_POINT& out) {
		PROGRAM_POINT p = {0};
		out = p;
		return true;
	}

private:
	uint64_t instrcnt;
	std::vector < addr_t > callers;

};

#endif

#ifdef RUNTEST

void test_isHex() {
	assert(isHex("abcdef012345"));
	assert(isHex("a"));
	assert(isHex("0"));
	assert(isHex("f"));
	assert(isHex("9"));
	assert(isHex("F"));
	assert(isHex("A"));
	assert(!isHex(""));
	assert(!isHex("not-hex"));
	assert(!isHex(" "));
	assert(!isHex("\r"));
	assert(!isHex("\n"));
	assert(!isHex("\t"));
}

void test_isDec() {
	assert(isDec("0123456789"));
	assert(!isDec(""));
	assert(isDec("0"));
	assert(isDec("9"));
	assert(!isDec("A"));
	assert(!isDec("F"));
	assert(!isDec("a"));
	assert(!isDec("f"));
	assert(!isDec("not-dec"));
	assert(!isDec(" "));
	assert(!isDec("\r"));
	assert(!isDec("\n"));
	assert(!isDec("\t"));
}

void test_parseCsv_expectSuccess() {
	// test parseCsv
	std::vector < std::string > out;
	bool res = parseCsv("1,2,3,4,5", ',', out);

	assert(out.size() == 5);
	for (int i=0; i<out.size(); ++i) {
		assert((i+1) == atoi(out[i].c_str()));
	}
	printf("Test parseCsv1 success\n");
}

void test_parseCsv_az09_expectSuccess() {
	// test parseCsv2
	std::vector < std::string > out;
	bool res = parseCsv("stra1,stra2,stra3", ',', out);

	const char * expected[] = {
		"stra1", "stra2", "stra3"
	};

	assert(out.size() == sizeof(expected) / sizeof(expected[0]));
	for (int i=0; i<out.size(); ++i) {
		assert(strcmp(expected[i], out[i].c_str()) == 0);
	}
	printf("Test parseCsv2 success\n");
}

void test_parseCsv_oneElem_expectSuccess() {
	// test parseCsv2
	std::vector < std::string > out;
	bool res = parseCsv("stra1", ',', out);

	const char * expected[] = {
		"stra1"
	};

	assert(out.size() == sizeof(expected) / sizeof(expected[0]));
	for (int i=0; i<out.size(); ++i) {
		assert(strcmp(expected[i], out[i].c_str()) == 0);
	}
	printf("Test parseCsv oneElem success\n");
}

void test_parseCsv_EmptyString_expect1ElemEmptyStrVector() {
	// test parseCsv2
	std::vector < std::string > out;
	bool res = parseCsv("", ',', out);

	const char * expected[] = {
		""
	};

	assert(out.size() == 1);
	assert(out[0] == "");
	printf("Test parseCsv emptyString success\n");
}

void test_initEngine_expectSuccess() {
	// test parsing config
	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "7fff;8fff;9fff";
	param.pidCsv = "10;20;30";
	param.pEnv = &env;
	param.csv_separator = ';';
	AnalysisEngine eng(param);

	bool initret = eng.init();
	assert(initret);

	const std::map < asid_t, proccess_id_t >& asid2pid = eng.getAsid2Pid();
	assert(asid2pid.size() == 3);
	assert(asid2pid.find(0x7fff)->second == 10);
	assert(asid2pid.find(0x8fff)->second == 20);
	assert(asid2pid.find(0x9fff)->second == 30);

	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	assert(processes.size() == 3);
	assert(processes.find(10) != processes.end());
	assert(processes.find(20) != processes.end());
	assert(processes.find(30) != processes.end());
		
	printf("Test AnalysisEngine init success\n");
}

void test__getHighestLayerProxy_expectSuccess() {
	// test highest layer proxy
	DummyEnv env;

	std::map < addr_t, SHADOW_BYTE > shadowMemory;
	for (addr_t addr = 0x1000; addr < 0x1004; ++addr) {
		SHADOW_BYTE sb;
		sb.layerNumber = addr - 0x1000 + 1;
		shadowMemory[addr] = sb;
	}

	ANALYSIS_PARAM param;
	param.asidCsv = "0";
	param.pidCsv = "0";
	param.pEnv = &env;
	AnalysisEngine eng(param);

	assert(eng._getHighestLayerProxy(shadowMemory, 0x1004, 4) == 0);
	assert(eng._getHighestLayerProxy(shadowMemory, 0x1000, 4) == 4);
	assert(eng._getHighestLayerProxy(shadowMemory, 0x1001, 4) == 4);
	assert(eng._getHighestLayerProxy(shadowMemory, 0x1002, 4) == 4);
	assert(eng._getHighestLayerProxy(shadowMemory, 0x1003, 4) == 4);
	assert(eng._getHighestLayerProxy(shadowMemory, 0x0FFF, 4) == 3);
	assert(eng._getHighestLayerProxy(shadowMemory, 0x0FFE, 4) == 2);
	assert(eng._getHighestLayerProxy(shadowMemory, 0x0FFD, 4) == 1);
	assert(eng._getHighestLayerProxy(shadowMemory, 0x0FFC, 4) == 0);

	printf("Test _getHighestLayer success\n");
}

void test__markWritten_expectAllSetWritten() {
	// test _markWritten
	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000";
	param.pidCsv = "1456";
	param.pEnv = &env;
	AnalysisEngine eng(param);

	assert(eng.init());

	eng._markWrittenProxy((addr_t)0xabcde000, 0x1000);
	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();

	const PROCESS_DATA& pd = processes.find(1456)->second;
	const SHADOW_BYTE& pb = pd.shadowMemory.find(0x1000)->second;

	assert(pb.memState == MEMSTATE_WRITTEN);
	assert(pb.nfFlag == true);
	assert(pb.nWritten == 1);

	eng._markWrittenProxy((addr_t)0xabcde000, 0x1000);

	assert(pb.memState == MEMSTATE_WRITTEN);
	assert(pb.nfFlag == true);
	assert(pb.nWritten == 2);

	eng._markWrittenProxy((addr_t)0xabcde000, 0x1000);

	assert(pb.memState == MEMSTATE_WRITTEN);
	assert(pb.nfFlag == true);
	assert(pb.nWritten == 3);

	printf("Test _markWritten success\n");
}

void test_onBeforeInsnTranslate_wrongAsid1_expectError() {
	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000";
	param.pidCsv = "1456";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	AnalysisEngine eng(param);

	assert(eng.init());

	{
		EXEC_ENV_PARAM env_param;
		env_param.asid = 0x12345678;

		INS_PARAM ins_param;
		ins_param.addr = 0x5000;
		ins_param.size = DUMMY_INSTR_SIZE;
		ins_param.buf = DUMMY_INSTR;
		int notr = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(notr == 0);
	}
}

void test_onBeforeInsnTranslate_wrongEIP_expectError() {

	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000";
	param.pidCsv = "1456";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	AnalysisEngine eng(param);

	assert(eng.init());

	{
		EXEC_ENV_PARAM env_param;
		env_param.asid = (addr_t)0xabcde000;

		INS_PARAM ins_param;
		ins_param.addr = 0x7fff0010;
		ins_param.size = DUMMY_INSTR_SIZE;
		ins_param.buf = DUMMY_INSTR;
		int notr = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(notr == 0);
	}
}

void test_onBeforeInsnTranslate_expectSuccess() {
	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000";
	param.pidCsv = "1456";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	AnalysisEngine eng(param);

	assert(eng.init());

	{
		EXEC_ENV_PARAM env_param;
		env_param.asid = (addr_t)0xabcde000;
		env_param.pid = 1456;
		env_param.tid = 100;

		INS_PARAM ins_param;
		ins_param.addr = 0x00401000;
		ins_param.size = 4;
		ins_param.buf = DUMMY_INSTR;
		int trr = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(trr == 1);

		// highest layer should be 0
		const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();

		const PROCESS_DATA& proc = processes.find(env_param.pid)->second;
		assert(proc.asid == env_param.asid);
		assert(proc.pid == env_param.pid);

		assert(proc.layers.size() == 1);

		const PROCESS_LAYER& proc_layer = proc.layers.find(0)->second;
		assert(proc_layer.layerNumber == 0);
			
		for (int i=0; i<ins_param.size; ++i) {
			addr_t addr = ins_param.addr + i;

			auto xit = proc_layer.executed.find(addr);
			assert(xit != proc_layer.executed.end());
			assert(xit->second.addr == addr);
		}
	}

	printf("Test onBeforeInsnTranslate success\n");

}

void test_TranslateExecWriteExec_expectSuccess() {

	// test full translate -> exec -> write -> exec

	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000";
	param.pidCsv = "1456";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	AnalysisEngine eng(param);

	assert(eng.init());

	{
		// translate
		EXEC_ENV_PARAM env_param;
		env_param.asid = (addr_t)0xabcde000;
		env_param.pid = 1456;
		env_param.tid = 100;

		INS_PARAM ins_param;
		ins_param.addr = 0x00401000;
		ins_param.size = 4;
		ins_param.buf = DUMMY_INSTR;

		int trr = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(trr == 1);

		const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
		const PROCESS_DATA& pd = processes.find(1456)->second;
		const PROCESS_LAYER& pl = pd.layers.find(0)->second;

		for (int i=0; i<ins_param.size; ++i) {
			addr_t a = ins_param.addr + i;
			assert(pl.executed.find(a) != pl.executed.end());
			const PROCESS_EXECUTED_BYTE& xb = pl.executed.find(a)->second;
			assert(xb.addr == a);
		}

		printf("        pt1. Test onBeforeInsnTranslate success\n");
	}

	{
		// exec
		EXEC_ENV_PARAM env_param;
		env_param.asid = (addr_t)0xabcde000;
		env_param.pid = 1456;
		env_param.tid = 100;

		INS_PARAM ins_param;
		ins_param.addr = 0x00401000;
		ins_param.size = 4;
		ins_param.buf = DUMMY_INSTR;

		eng.onBeforeInsnExec(env_param, ins_param, NULL);

		const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
		const PROCESS_DATA& pd = processes.find(1456)->second;
		const PROCESS_LAYER& pl = pd.layers.find(0)->second;
		//const PROCESS_EXECUTED_BYTE& xb = pl.executed.find(0x00401000)->second;

		for (int i=0; i<ins_param.size; ++i) {
			addr_t a = ins_param.addr + i;
			const SHADOW_BYTE& sb = pd.shadowMemory.find(a)->second;
			assert(sb.layerNumber == 0);
			assert(sb.memState == MEMSTATE_EXECUTED);
			assert(sb.nfFlag == false);
			assert(sb.nWritten == 0);
		}

		printf("        pt1. Test onBeforeInsnExec success\n");
			
	}

	{
		EXEC_ENV_PARAM env_param;
		env_param.asid = (addr_t)0xabcde000;
		env_param.pid = 1456;
		env_param.tid = 100;

		INS_PARAM ins_param;
		ins_param.addr = 0x00401000;
		ins_param.size = 4;
		ins_param.buf = DUMMY_INSTR;

		WRITE_PARAM wp;
		wp.addr = 0x00401002;
		wp.size = 2;

		// code rewrite
		eng.onBeforeWriteVirtAddr(env_param, ins_param, wp, NULL);

		printf("        pt2.1\n");

		const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
		const PROCESS_DATA& pd = processes.find(1456)->second;
		const PROCESS_LAYER& pl = pd.layers.find(0)->second;
		const PROCESS_EXECUTED_BYTE& xb = pl.executed.find(0x00401000)->second;

		printf("        pt2.2\n");

		TRIPLET(proccess_id_t, layer_t, addr_t) key = createAddrKey(env_param.pid, 1, wp.addr);
		assert(xb.writeCounters.find(key)->second == 1);

		TRIPLET(proccess_id_t, layer_t, addr_t) key_0 = createAddrKey(env_param.pid, 0, wp.addr);
		assert(xb.writeCounters.find(key_0) == xb.writeCounters.end());

		printf("        pt2.3\n");

		const SHADOW_BYTE& sb = pd.shadowMemory.find(wp.addr)->second;

		printf("        pt2.4\n");

		assert(sb.layerNumber == 1);
		assert(sb.memState == MEMSTATE_WRITTEN);
		assert(sb.nfFlag);
		assert(sb.nWritten == 1);

		assert(pl.addr_in_layer.find(0x00401000) != pl.addr_in_layer.end());
		assert(pl.addr_in_layer.find(0x00401001) != pl.addr_in_layer.end());
		assert(pl.addr_in_layer.find(0x00401002) == pl.addr_in_layer.end());
		assert(pl.addr_in_layer.find(0x00401003) == pl.addr_in_layer.end());
		assert(pd.layers.find(1) != pd.layers.end());
		assert(pd.layers.find(1)->second.addr_in_layer.find(0x00401002) != pd.layers.find(1)->second.addr_in_layer.end());
		assert(pd.layers.find(1)->second.addr_in_layer.find(0x00401003) != pd.layers.find(1)->second.addr_in_layer.end());

	}

	{
		// translate exec again
		EXEC_ENV_PARAM env_param;
		env_param.asid = (addr_t)0xabcde000;
		env_param.pid = 1456;
		env_param.tid = 100;

		INS_PARAM ins_param;
		ins_param.addr = 0x00401000;
		ins_param.size = 4;
		ins_param.buf = DUMMY_INSTR;

		int trr = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(trr == 1);

		const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
		const PROCESS_DATA& pd = processes.find(1456)->second;
		const PROCESS_LAYER& pl = pd.layers.find(1)->second;

		for (int i=0; i<ins_param.size; ++i) {
			addr_t a = ins_param.addr + i;
			assert(pl.executed.find(a) != pl.executed.end());
			const PROCESS_EXECUTED_BYTE& xb = pl.executed.find(a)->second;
			assert(xb.addr == a);
		}

		printf("        pt3. Test onBeforeInsnTranslate success\n");
	}

	{
		// test eexec again
		EXEC_ENV_PARAM env_param;
		env_param.asid = 0xabcde000;
		env_param.pid = 1456;
		env_param.tid = 100;

		INS_PARAM ins_param;
		ins_param.addr = 0x00401000;
		ins_param.size = 4;
		ins_param.buf = DUMMY_INSTR;

		eng.onBeforeInsnExec(env_param, ins_param, NULL);

		const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
		const PROCESS_DATA& pd = processes.find(1456)->second;
		const PROCESS_LAYER& pl = pd.layers.find(1)->second;
		const PROCESS_EXECUTED_BYTE& xb = pl.executed.find(0x00401000)->second;

		// check shadow bytes
		for (int i=0; i<ins_param.size; ++i) {
			addr_t a = ins_param.addr + i;
			const SHADOW_BYTE& sb = pd.shadowMemory.find(a)->second;
			assert(sb.layerNumber == 1);
			assert(sb.memState == MEMSTATE_EXECUTED);
			assert(sb.nfFlag == false);
			assert(sb.nWritten == 0);
		}

		// check transition counters
		TRIPLET(proccess_id_t, layer_t, addr_t) transition_key = createAddrKey(
			env_param.pid, 0, ins_param.addr);
		assert(xb.transitionCounters.find(transition_key) != xb.transitionCounters.end());
		assert(xb.transitionCounters.find(transition_key)->second == 1);

		printf("        pt4. Test onBeforeInsnExec success\n");
			
	}

	FILE* out = fopen("test_full_translate_exec_write_translate_exec_success.log", "w");
	eng.dumpLogs(out);
	fclose(out);

	printf("Test full translate -> exec -> write -> translate -> exec success\n");
}

void test_lastInstructionsAndGlobal_expectSuccess() {
	// test last instructions for multithreaded executables

	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000";
	param.pidCsv = "1456";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	AnalysisEngine eng(param);

	assert(eng.init());

	// translate
	EXEC_ENV_PARAM env_param;
	env_param.asid = (addr_t)0xabcde000;
	env_param.pid = 1456;

	INS_PARAM ea[3];
	for (int i=0; i<3; ++i) {
		ea[i].addr = 0x00601000 + i*4;
		ea[i].size = 4;
		ea[i].buf = DUMMY_INSTR;
	}

	// expected:
	INS_PARAM expected_last_insn[3];
	expected_last_insn[0] = ea[1];
	expected_last_insn[1] = ea[1];
	expected_last_insn[2] = ea[2];

	guest_insncnt_t expected_last_insn_guest_insncnt[3];
	expected_last_insn_guest_insncnt[0] = 4;
	expected_last_insn_guest_insncnt[1] = 2;
	expected_last_insn_guest_insncnt[2] = 3;

	{
		env_param.tid = 100;
		for (int i=0; i<3; ++i) {
			int trr = eng.onBeforeInsnTranslate(env_param, ea[i], NULL);
			assert(trr == 1);
		}
	}
	{
		env_param.tid = 100;
		eng.onBeforeInsnExec(env_param, ea[0], NULL);
	}
	{
		env_param.tid = 101;
		eng.onBeforeInsnExec(env_param, ea[1], NULL);
	}
	{
		env_param.tid = 102;
		eng.onBeforeInsnExec(env_param, ea[2], NULL);
	}
	{
		env_param.tid = 100;
		eng.onBeforeInsnExec(env_param, ea[1], NULL);
	}

	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	const PROCESS_DATA& pd = processes.find(env_param.pid)->second;
		
	assert(pd.lastInstrs.size() == 3);
	assert(pd.lastInstrs.find(100) != pd.lastInstrs.end());
	assert(pd.lastInstrs.find(101) != pd.lastInstrs.end());
	assert(pd.lastInstrs.find(102) != pd.lastInstrs.end());

	for (int i=100; i<=102; ++i) {
		const PROCESS_LAST_INSTRUCTION& last = pd.lastInstrs.find(i)->second;
		assert(last.addr == expected_last_insn[i-100].addr);
		assert(last.layer == 0);
		assert(last.owner_asid == env_param.asid);
		assert(last.owner_pid == env_param.pid);
		assert(last.size == expected_last_insn[i-100].size);

		//printf(">> t. i=%d, last insncnt=%lu\n", i, last.insncnt);
		assert(last.insncnt == expected_last_insn_guest_insncnt[i-100]);
	}

	printf("Test last instructions of 3 threads exec success\n");

	const PROCESS_LAST_INSTRUCTION& global_last = eng._get_global_last_instruction();
	{
		int i=100;
		assert(global_last.addr == expected_last_insn[i-100].addr);
		assert(global_last.layer == 0);
		assert(global_last.owner_asid == env_param.asid);
		assert(global_last.owner_pid == env_param.pid);
		assert(global_last.size == expected_last_insn[i-100].size);

		//printf(">> t. i=%d, last insncnt=%lu\n", i, global_last.insncnt);
		assert(global_last.insncnt == expected_last_insn_guest_insncnt[i-100]);
	}

	FILE* out = fopen("test_last_global_instructions.log", "w");
	eng.dumpLogs(out);
	fclose(out);

	printf("Test last global instructions\n");
}

void test_MultipleWrites_expectSuccess() {
	// test multiple writes

	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000";
	param.pidCsv = "1456";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	AnalysisEngine eng(param);

	assert(eng.init());

	EXEC_ENV_PARAM env_param;
	env_param.asid = (addr_t)0xabcde000;
	env_param.pid = 1456;
	env_param.tid = 6780;

	INS_PARAM ins_param;
	ins_param.addr = 0x00501000;
	ins_param.size = 4;
	ins_param.buf = DUMMY_INSTR;

	WRITE_PARAM wp;
	wp.addr = 0x009FFF00;
	wp.size = 4;

	{
		int tsn = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(tsn == 1);
	}
	for (int i=0; i<4; ++i) {
		{
			eng.onBeforeInsnExec(env_param, ins_param, NULL);
		}
		{
			// code does write and rewrite
			eng.onBeforeWriteVirtAddr(env_param, ins_param, wp, NULL);
		}
	}

	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	const PROCESS_DATA& pd = processes.find(atoi(param.pidCsv))->second;
	const PROCESS_LAYER& pl = pd.layers.find(0)->second;
	const PROCESS_EXECUTED_BYTE& xb = pl.executed.find(ins_param.addr)->second;

	TRIPLET(proccess_id_t, layer_t, addr_t) key = createAddrKey(env_param.pid, 1, wp.addr);
	assert(xb.writeCounters.find(key)->second == 4);

	TRIPLET(proccess_id_t, layer_t, addr_t) key_0 = createAddrKey(env_param.pid, 0, wp.addr);
	assert(xb.writeCounters.find(key_0) == xb.writeCounters.end());

	const SHADOW_BYTE& sb = pd.shadowMemory.find(wp.addr)->second;

	assert(sb.layerNumber == 1);
	assert(sb.memState == MEMSTATE_WRITTEN);
	assert(sb.nfFlag);
	assert(sb.nWritten == 4);

	assert(pl.addr_in_layer.find(wp.addr) == pl.addr_in_layer.end());
	assert(pd.layers.find(1) != pd.layers.end());
	assert(pd.layers.find(1)->second.addr_in_layer.find(wp.addr) != pd.layers.find(1)->second.addr_in_layer.end());

	FILE* out = fopen("test_multi_writes.log", "w");
	eng.dumpLogs(out);
	fclose(out);

	printf("Test multi writes success\n");
}

void test_WriteToOtherProcess_expectSuccess() {
	// test writes to other process

	//DummyEnv env;
	// callers from panda are the NEXT instruction AFTER the call instruction!!!
	static const addr_t callers[] = {
		0x7fff0040,
		0x654300ff,
		0x0040120a
	};

	DummyEnvWithCaller env(callers, sizeof(callers)/sizeof(callers[0]));
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000;000edcba";
	param.pidCsv = "1456;6541";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	param.csv_separator = ';';
	AnalysisEngine eng(param);

	assert(eng.init());

	EXEC_ENV_PARAM env_param;
	env_param.asid = (asid_t)0xabcde000;
	env_param.pid = 1456;
	env_param.tid = 100;

	// simulate API call / syscall.
	INS_PARAM ins_param;
	ins_param.addr = callers[2] - 4; // think that this is a CALL x86 instruction BEFORE the caller from callers array!!!
	ins_param.size = 4;
	ins_param.buf = DUMMY_INSTR;

	WRITE_PARAM write_param;
	write_param.size = 16;
	write_param.addr = 0x09ff2340;

	{
		int tsn = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(tsn == 1);

		eng.onBeforeInsnExec(env_param, ins_param, NULL);
	}

	eng.onBeforeApiMemoryWriteBulk(0x000edcba, env_param, write_param, NULL);

	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	const PROCESS_DATA& pd = processes.find(1456)->second;
	const PROCESS_LAYER& pl = pd.layers.find(0)->second;
	const PROCESS_EXECUTED_BYTE& xb = pl.executed.find(ins_param.addr)->second;

	for (int i=0; i<16; ++i) {
		TRIPLET(proccess_id_t, layer_t, addr_t) key = createAddrKey(6541, 1, 0x09ff2340 + i);
		assert(xb.writeCounters.find(key)->second == 1);
	}

	FILE* out = fopen("test_writes_to_other_process.log", "w");
	eng.dumpLogs(out);
	fclose(out);

	printf("Test writes to other process success\n");
}

void test_onCreateHeap_1x_expectSuccess() {
	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "0071a000;4310a000";
	param.pidCsv = "4510;821";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	param.csv_separator = ';';
	AnalysisEngine eng(param);

	assert(eng.init());

	EXEC_ENV_PARAM xp;
	xp.asid = 0x71a000;
	xp.pid = 4510;
	xp.tid = 100;

	addr_t heapAddr = 0x00400000;
	uint32_t heapSize = 0x1000;

	eng.onCreateHeap(xp, heapAddr, heapSize, NULL);

	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	assert(processes.find(4510) != processes.end());
	
	const PROCESS_DATA& pd = processes.find(4510)->second;
	const std::map < addr_t, HEAP_MEMORY >& heapMemory = pd.heapMemory;
	
	assert(heapMemory.size() == 1);
	assert(heapMemory.find(heapAddr) != heapMemory.end());
	const HEAP_MEMORY& heap = heapMemory.find(heapAddr)->second;
	assert(heap.length == heapSize);
	assert(heap.startAddr == heapAddr);

	const PROCESS_DATA& opd = processes.find(821)->second;
	assert(opd.heapMemory.find(heapAddr) == opd.heapMemory.end());

	printf("test_onCreateHeap_1x_expectSuccess success\n");

}

void test_onCreateHeap_1x1u_expectSuccess() {
	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "0071a000;4310a000";
	param.pidCsv = "4510;821";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	param.csv_separator = ';';
	AnalysisEngine eng(param);

	assert(eng.init());

	EXEC_ENV_PARAM xp;
	xp.asid = 0x71a000;
	xp.pid = 4510;
	xp.tid = 100;

	addr_t heapAddr = 0x00400000;
	uint32_t heapSize = 0x1000;
	uint32_t heapSize2 = 0x2000;

	eng.onCreateHeap(xp, heapAddr, heapSize, NULL);
	eng.onCreateHeap(xp, heapAddr, heapSize2, NULL);

	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	assert(processes.find(4510) != processes.end());
	
	const PROCESS_DATA& pd = processes.find(4510)->second;
	const std::map < addr_t, HEAP_MEMORY >& heapMemory = pd.heapMemory;
	
	assert(heapMemory.size() == 1);
	assert(heapMemory.find(heapAddr) != heapMemory.end());
	const HEAP_MEMORY& heap = heapMemory.find(heapAddr)->second;
	assert(heap.length == heapSize2);
	assert(heap.startAddr == heapAddr);

	printf("test_onCreateHeap_1x1u_expectSuccess success\n");

}

void test_onCreateRemoveHeap_1x1d_expectSuccess() {
	DummyEnv env;
	ANALYSIS_PARAM param;
	param.asidCsv = "0071a000;4310a000";
	param.pidCsv = "4510;821";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	param.csv_separator = ';';
	AnalysisEngine eng(param);

	assert(eng.init());

	EXEC_ENV_PARAM xp;
	xp.asid = 0x71a000;
	xp.pid = 4510;
	xp.tid = 100;

	addr_t heapAddr = 0x00400000;
	uint32_t heapSize = 0x1000;

	eng.onCreateHeap(xp, heapAddr, heapSize, NULL);
	eng.onRemoveHeap(xp, heapAddr, NULL);

	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	assert(processes.find(4510) != processes.end());
	
	const PROCESS_DATA& pd = processes.find(4510)->second;
	const std::map < addr_t, HEAP_MEMORY >& heapMemory = pd.heapMemory;
	
	assert(heapMemory.size() == 0);

	printf("test_onCreateRemoveHeap_1x1d_expectSuccess success\n");
}

void test_writeRemoteProcessAndExec_expectSuccess() {
	// test writes to other process

	//DummyEnv env;
	static const addr_t callers[] = {
		0x7fff0040,
		0x654300ff,
		0x0040120a
	};

	DummyEnvWithCaller env(callers, sizeof(callers)/sizeof(callers[0]));
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000;000edcba";
	param.pidCsv = "1456;6541";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	param.csv_separator = ';';
	AnalysisEngine eng(param);

	assert(eng.init());

	EXEC_ENV_PARAM env_param;
	env_param.asid = (asid_t)0xabcde000;
	env_param.pid = 1456;
	env_param.tid = 100;

	EXEC_ENV_PARAM remote_env;
	remote_env.asid = 0x000edcba;
	remote_env.pid = 6541;
	remote_env.tid = 250;

	// simulate API call / syscall.
	INS_PARAM ins_param;
	ins_param.addr = callers[2] - 4; // think that this is a CALL x86 instruction
									 // must be -4 because don't forget, callers are actually the return address after the call is done
									 // thus, it is ALWAYS the NEXT instruction AFTER the call is performed.
	ins_param.size = 4;
	ins_param.buf = DUMMY_INSTR;

	WRITE_PARAM write_param;
	write_param.size = 16;
	write_param.addr = 0x09ff2340;

	INS_PARAM remote_ins;
	remote_ins.addr = write_param.addr;
	remote_ins.buf = DUMMY_INSTR;
	remote_ins.size = 4;

	{
		int tsn = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(tsn == 1);

		eng.onBeforeInsnExec(env_param, ins_param, NULL);
	}

	eng.onBeforeApiMemoryWriteBulk(0x000edcba, env_param, write_param, NULL);

	{
		// execute in other process
		assert(eng.onBeforeInsnTranslate(remote_env, remote_ins, NULL) == 1);
		eng.onBeforeInsnExec(remote_env, remote_ins, NULL);
	}

	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	const PROCESS_DATA& pd = processes.find(1456)->second;
	const PROCESS_LAYER& pl = pd.layers.find(0)->second;
	const PROCESS_EXECUTED_BYTE& xb = pl.executed.find(ins_param.addr)->second;

	for (int i=0; i<16; ++i) {
		TRIPLET(proccess_id_t, layer_t, addr_t) key = createAddrKey(6541, 1, 0x09ff2340 + i);
		assert(xb.writeCounters.find(key)->second == 1);
	}

	const PROCESS_DATA& rpd = processes.find(6541)->second;
	assert(rpd.layers.size() == 1);
	assert(rpd.layers.find(1) != rpd.layers.end());
	const PROCESS_LAYER& rpdl1 = rpd.layers.find(1)->second;
	assert(rpdl1.layerNumber == 1);
	for (int i=0; i<remote_ins.size; ++i) {
		addr_t ra = remote_ins.addr + i;
		assert(rpdl1.addr_in_layer.find(ra) != rpdl1.addr_in_layer.end());
		assert(rpdl1.byte_info.find(ra) != rpdl1.byte_info.end());
		assert(rpdl1.byte_info.find(ra)->second.nFrames == 1);
		assert(rpdl1.executed.find(ra) != rpdl1.executed.end());
	}

	FILE* out = fopen("test_writes_to_other_process_and_execd.log", "w");
	eng.dumpLogs(out);
	fclose(out);

	printf("test_writeRemoteProcessAndExec_expectSuccess\n");
}

void test_classify_api() {
	
	assert(api_filter::classify_api("GetVersion") == api_filter::API_GROUP_GETVERSION);
	assert(api_filter::classify_api("GetVersionEx") == api_filter::API_GROUP_GETVERSION);
	assert(api_filter::classify_api("GetVersionExW") == api_filter::API_GROUP_GETVERSION);
	assert(api_filter::classify_api("GetCommandLine") == api_filter::API_GROUP_GETCOMMANDLINE);
	assert(api_filter::classify_api("GetCommandLineW") == api_filter::API_GROUP_GETCOMMANDLINE);
	assert(api_filter::classify_api("GetModuleHandleA") == api_filter::API_GROUP_GETMODULEHANDLE);
	assert(api_filter::classify_api("GetModuleHandleW") == api_filter::API_GROUP_GETMODULEHANDLE);
	assert(api_filter::classify_api("GetModuleHandleExA") == api_filter::API_GROUP_GETMODULEHANDLE);
	assert(api_filter::classify_api("GetModuleHandleExW") == api_filter::API_GROUP_GETMODULEHANDLE);
	assert(api_filter::classify_api("MessageBox") == api_filter::API_GROUP_MESSAGEBOX);
	assert(api_filter::classify_api("MessageBoxExW") == api_filter::API_GROUP_MESSAGEBOX);
	assert(api_filter::classify_api("MessageBoxInternalW") == api_filter::API_GROUP_MESSAGEBOX);
	assert(api_filter::classify_api("GetVersiox") == api_filter::API_GROUP_OTHERS);
	assert(api_filter::classify_api("GetCommandLino") == api_filter::API_GROUP_OTHERS);
	assert(api_filter::classify_api("GetModuleHandlo") == api_filter::API_GROUP_OTHERS);
	assert(api_filter::classify_api("MessageBon") == api_filter::API_GROUP_OTHERS);
	assert(api_filter::classify_api("OtherApiCall") == api_filter::API_GROUP_OTHERS);
	
	printf("test_classify_api()\n");
}

void test_apiCounter_expectSuccess() {
	
	static const addr_t callers[] = {
		0x7fff0040,
		0x654300ff,
		0x0040120a
	};

	DummyEnvWithCaller env(callers, sizeof(callers)/sizeof(callers[0]));
	ANALYSIS_PARAM param;
	param.asidCsv = "abcde000";
	param.pidCsv = "1456";
	param.pEnv = &env;
	param.startAnalysisAddr = 0x0;
	param.endAnalysisAddr = 0x10000000;
	AnalysisEngine eng(param);

	assert(eng.init());

	EXEC_ENV_PARAM env_param;
	env_param.asid = (asid_t)0xabcde000;
	env_param.pid = 1456;
	env_param.tid = 100;

	// simulate API call / syscall.
	INS_PARAM ins_param;
	ins_param.addr = callers[2] - 4; // think that this is a CALL x86 instruction
									 // must be -4 because don't forget, callers are actually the return address after the call is done
									 // thus, it is ALWAYS the NEXT instruction AFTER the call is performed.
	ins_param.size = 4;
	ins_param.buf = DUMMY_INSTR;

	{
		int tsn = eng.onBeforeInsnTranslate(env_param, ins_param, NULL);
		assert(tsn == 1);

		eng.onBeforeInsnExec(env_param, ins_param, NULL);
	}
	
	API_CALL_PARAM api_call_param;
	api_call_param.api_name = "GetVersionEx";
	api_call_param.api_va = 0x7012abcd;
	eng.onBeforeApiCall(env_param, api_call_param, NULL);
	
	const std::map < proccess_id_t, PROCESS_DATA >& processes = eng.getProcesses();
	const PROCESS_DATA& pd = processes.find(1456)->second;
	const PROCESS_LAYER& pl = pd.layers.find(0)->second;
	const auto& counter_map = pl.api_counter_byte;
	
	assert(counter_map.find(ins_param.addr) != counter_map.end());
	const PROCESS_API_CALL_COUNTER_BYTE& counter_byte = counter_map.find(ins_param.addr)->second;
	assert(counter_byte.addr == ins_param.addr);
	
	{
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_GETVERSION) != 
		counter_byte.api_group_counter_map.end());
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_GETVERSION)->second == 1);
	}
	
	// call again
	eng.onBeforeApiCall(env_param, api_call_param, NULL);
	{
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_GETVERSION)->second == 2);
	}
	
	{
		assert(counter_byte.api_counter_map.find(api_call_param.api_va) != counter_byte.api_counter_map.end());
		assert(counter_byte.api_counter_map.find(api_call_param.api_va)->second == 2);
	}
	
	API_CALL_PARAM otherapi;
	otherapi.api_name = "CallOtherApis";
	otherapi.api_va = 0x6012abcd;
	eng.onBeforeApiCall(env_param, otherapi, NULL);
	
	{
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_OTHERS) != counter_byte.api_group_counter_map.end());
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_OTHERS)->second == 1);
		
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_GETVERSION) != counter_byte.api_group_counter_map.end());
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_GETVERSION)->second == 2);
		
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_MESSAGEBOX) == counter_byte.api_group_counter_map.end());
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_GETCOMMANDLINE) == counter_byte.api_group_counter_map.end());
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_GETMODULEHANDLE) == counter_byte.api_group_counter_map.end());
		assert(counter_byte.api_group_counter_map.find(api_filter::API_GROUP_NONE) == counter_byte.api_group_counter_map.end());
	}
	
	{
		assert(counter_byte.api_counter_map.find(otherapi.api_va) != counter_byte.api_counter_map.end());
		assert(counter_byte.api_counter_map.find(otherapi.api_va)->second == 1);
	}
	
	FILE* out = fopen("test_api_call_logs.log", "w");
	eng.dumpLogs(out);
	fclose(out);
	
	printf("test_apiCounter_expectSuccess success\n");
}

int main() {

	tracer::TrcInit("trctrace.log", 31);

	test_isHex();
	test_isDec();
	test_parseCsv_expectSuccess();
	test_parseCsv_az09_expectSuccess();
	test_parseCsv_EmptyString_expect1ElemEmptyStrVector();
	test_parseCsv_oneElem_expectSuccess();
	test_initEngine_expectSuccess();
	test__getHighestLayerProxy_expectSuccess();
	test__markWritten_expectAllSetWritten();
	test_onBeforeInsnTranslate_wrongAsid1_expectError();
	test_onBeforeInsnTranslate_wrongEIP_expectError();
	test_onBeforeInsnTranslate_expectSuccess();
	test_TranslateExecWriteExec_expectSuccess();
	test_lastInstructionsAndGlobal_expectSuccess();
	test_MultipleWrites_expectSuccess();
	test_WriteToOtherProcess_expectSuccess();
	test_onCreateHeap_1x_expectSuccess();
	test_onCreateHeap_1x1u_expectSuccess();
	test_onCreateRemoveHeap_1x1d_expectSuccess();
	test_writeRemoteProcessAndExec_expectSuccess();
	test_classify_api();
	test_apiCounter_expectSuccess();

	tracer::TrcClose();

	printf("Close? [y]> ");
	getchar();

}

#endif