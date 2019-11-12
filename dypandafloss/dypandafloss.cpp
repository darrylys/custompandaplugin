/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plugin_plugin.h"

#include "dbgdefs.h"

#include <stdint.h>
#include <stdio.h>

#include <map>
#include <vector>
#include <string>
#include <stack>
#include <set>
#include <sstream>

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

#include "ProcParam.h"
#include "IProcFilter.h"
#include "ArithmeticFilter.h"
#include "MovFilter.h"
#include "ShiftFilter.h"
#include "XorFilter.h"

#define G_PLUGIN_NAME "dypandafloss"

std::set<std::string> utf16leSet;
std::set<std::string> asciiSet;
typedef std::set<std::string>::iterator StringSetIterator;

typedef struct _INSN {
    target_ulong addr;
    uint32_t size;
    bool recordWrite;
} INSN;
std::map<uint64_t, INSN> recordMemWriteMap;
typedef std::map<uint64_t, INSN>::iterator recordMemWriteMapIt;

typedef struct _MEMWRITERECORD {
    target_ulong writeAddr;
    target_ulong writeValue;
    target_ulong size;
    target_ulong writeInsnAddr;
    uint64_t writeInstrCnt;
} MEMWRITERECORD;

typedef struct _CALLRETURN {
    target_ulong callAddr;
    target_ulong retAddr;
    target_ulong esp;
    target_ulong caller;
    
    // key = write address, value = write value
    std::map<target_ulong, MEMWRITERECORD> memWriteMap;
} CALLRETURN;
typedef std::map<target_ulong, MEMWRITERECORD>::iterator memWriteMapIt;
typedef std::map<target_ulong, MEMWRITERECORD>::const_iterator memWriteMapConstIt;

typedef struct _CALLSTACK {
    std::stack<CALLRETURN> callStack;
} CALLSTACK;
// key is thread id.
std::map<target_ulong, CALLSTACK> tidCallStackMap;
typedef std::map<target_ulong, CALLSTACK>::iterator tidCallStackMapIt;
typedef std::map<target_ulong, CALLSTACK>::const_iterator tidCallStackMapConstIt;

// This map is for marking code after call is executed. This is because 
// after_insn_exec does not seem to finish executing "call" instruction.
// key is thread id, value = address of caller
std::map<target_ulong, target_ulong> tidIsCallExecutedMap;
typedef std::map<target_ulong, target_ulong>::iterator tidIsCallExecutedMapIt;
typedef std::map<target_ulong, target_ulong>::const_iterator tidIsCallExecutedMapConstIt;

std::vector<IProcFilter*> procFilterList;

FILE * gOutputFile;

bool gCapstoneOpened;
csh gCapstoneHandle;
target_ulong gTargetAsid;
target_ulong gStartAnalysisAddr;
target_ulong gEndAnalysisAddr;

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

bool isRunningAnalysisHere(CPUState* env, target_ulong pc) {
    target_ulong currentAsid = panda_current_asid(env);
    if (currentAsid != gTargetAsid) {
        return false;
    }
    
    // dummy way to exclude all library codes
    if (pc < gStartAnalysisAddr || pc >= gEndAnalysisAddr) {
        return false;
    }
    
    return true;
}

/**
* Reads Process ID of current process.
* Only tested on Windows 7 x86 SP1.
*/
target_ulong get_pid(CPUState* env) {
#ifdef TARGET_I386
    CPUArchState *arch = reinterpret_cast<CPUArchState*> (env->env_ptr);
    target_ulong fs = arch->segs[R_FS].base;
    target_ulong fs_pid;
    if (-1 == panda_virtual_memory_read(env, fs + 0x20, (uint8_t*) (&fs_pid), sizeof (fs_pid))) {
        return 0;
    } else {
        return fs_pid;
    }
#endif
    return 0; // 0 is idle process, which means invalid for our purposes.
}

/**
 * Reads Thread ID of currently running thread.
 * Only tested on Windows 7 x86 SP1.
 */
target_ulong get_tid(CPUState* env) {
#ifdef TARGET_I386
    CPUArchState *arch = reinterpret_cast<CPUArchState*> (env->env_ptr);
    target_ulong fs = arch->segs[R_FS].base;
    target_ulong fs_tid;
    if (-1 == panda_virtual_memory_read(env, fs + 0x24, (uint8_t*) (&fs_tid), sizeof (fs_tid))) {
        return 0;
    } else {
        return fs_tid;
    }
#endif
    return 0; // 0 is an invalid thread, according to MSDN and Raymond Chen
}

int pcbOnVirtMemWrite(CPUState *env, target_ulong pc, target_ulong addr, 
        target_ulong size, void *buf) {
    
#if defined(TARGET_I386)
    
    if (!isRunningAnalysisHere(env, pc)) {
        return 0;
    }
    
    recordMemWriteMapIt it = recordMemWriteMap.find(pc);
    if (it == recordMemWriteMap.end() || !it->second.recordWrite) {
        return 0;
    }
    
    CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
    target_ulong ebp = arch->regs[R_EBP];
    if (addr > ebp) { // record writes outside current stack
        
        // size MAX 8
        uint64_t data = 0;
        uint8_t *pData = reinterpret_cast<uint8_t*>(&data);
        uint8_t *pBuf = reinterpret_cast<uint8_t*>(buf);
        for (uint32_t i=0; i<size; ++i) {
            *(pData+i) = *(pBuf+i);
        }
        
//        fprintf(gOutputFile, "%08x %08x %d %lx (%c)\n", 
//                (uint32_t)pc, (uint32_t)addr, (uint32_t)size, 
//                data, (char)(data & 0xFF));
        
        target_ulong currentTid = get_tid(env);
        tidCallStackMapIt stackIt = tidCallStackMap.find(currentTid);
        if (stackIt == tidCallStackMap.end()) {
            return 0;
        }
        
        CALLSTACK& callStack = stackIt->second;
        if (callStack.callStack.empty()) {
            return 0;
        }
        
        RR_prog_point pp = rr_prog_point();
        CALLRETURN& retData = callStack.callStack.top();
        MEMWRITERECORD wr;
        wr.size = size;
        wr.writeAddr = addr;
        wr.writeValue = data;
        wr.writeInsnAddr = pc;
        wr.writeInstrCnt = pp.guest_instr_count;
        retData.memWriteMap[addr] = wr;
    }
    
#endif
    
    return 0;
}

int pcbAfterBlockTranslate(CPUState* cpu, TranslationBlock* tb) {
    
#if defined(TARGET_I386)
    
    if (!isRunningAnalysisHere(cpu, tb->pc)) {
        return 0;
    }
    
    uint64_t startAddr = (uint64_t)(tb->pc);
    std::vector<uint8_t> vBuf(tb->size + 10);
    
    if (-1 == panda_virtual_memory_read(cpu, tb->pc, &(vBuf[0]), tb->size)) {
        fprintf(stderr, "[error] Unable to read translation block at 0x%08x size 0x%08x\n", 
                (uint32_t)tb->pc, (uint32_t)tb->size);
        return 1;
    }
    
    fprintf(stderr, "[debug] Start disasm code at address 0x%08x, size 0x%08x\n", 
                (uint32_t)startAddr, (uint32_t)tb->size);
    
    cs_insn *insn;
    size_t count;
    // disasm stopped at first error, which is probably okay for now
    count = cs_disasm(gCapstoneHandle, &(vBuf[0]), tb->size, startAddr, 0, &insn);
    if (count > 0) {
        
        ProcParam procParam;
        procParam.count = count;
        procParam.insn = insn;
        
        double score = 0.0;
        
        fprintf(stderr, "[debug] analyzing code at address 0x%08x, size 0x%08x\n", 
                (uint32_t)startAddr, (uint32_t)tb->size);
        
        // for debugging
        for (size_t j = 0; j < count; ++j) {
            fprintf(stderr, "[debug] disasm: 0x%" PRIx64 ":\t%s\t\t%s\n", 
                    insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        
        int procFilterListSize = procFilterList.size();
        for (int X = 0; X < procFilterListSize; ++X) {
            IProcFilter* pf = procFilterList[X];
            
            double t = 0;
            t = pf->analyse(&procParam);
            fprintf(stderr, "[debug] Filter [%s] = [%lf]\n", pf->getName(), t);
            
            score += t;
        }
        
        fprintf(stderr, "[debug] total score: %lf\n", score);
        
        bool record = false;
        if (score > 0.0) {
            // log all writes in this basic block
            fprintf(stderr, "[debug] record this basic block!\n");
            record = true;
        }

        for (size_t j = 0; j < count; ++j) {
//          fprintf(stderr, "[debug] disasm: 0x%"PRIx64":\t%s\t\t%s\n", 
//                   insn[j].address, insn[j].mnemonic, insn[j].op_str);
            INSN& recordInsn = recordMemWriteMap[insn[j].address];
            recordInsn.addr = (target_ulong)insn[j].address;
            recordInsn.recordWrite = record;
            recordInsn.size = insn[j].size;
        }
        
        cs_free(insn, count);
    } else {
        fprintf(stderr, "[error] Failed to disassemble code at address 0x%08x size 0x%08x\n", 
                (uint32_t)startAddr, (uint32_t)tb->size);
    }
    
#endif
    
    return 0;
}

// if return true, adds instrumentation on callback before_insn_exec
bool pcbOnBeforeInsnTranslate(CPUState* cpu, target_ulong pc) {
    return false;
}

// if return true, adds instrumentation on callback after_insn_exec
bool pcbOnAfterInsnTranslate(CPUState* cpu, target_ulong pc) {
    
#if defined(TARGET_I386)
    
    if (!isRunningAnalysisHere(cpu, pc)) {
        return false;
    }
    
    // check call, and return.
    // instrument calls
    
    uint8_t buf[32];
    if (-1 == panda_virtual_memory_read(cpu, pc, buf, sizeof(buf))) {
        fprintf(stderr, "[error] failed to read code at address 0x%08x\n", (uint32_t)pc);
        return false;
    }
    
    // just disassemble 1 instruction.
    cs_insn * insn;
    size_t count = cs_disasm(gCapstoneHandle, buf, sizeof(buf), pc, 1, &insn);
    if (count > 0) {
        
        bool instrumentCall = false;
        if (strcasecmp("call", insn[0].mnemonic) == 0) {
            fprintf(stderr, "[debug] instrument \"call\" at 0x%08lx\n", insn[0].address);
            instrumentCall = true;
        }
        
        cs_free(insn, count);
        return instrumentCall;
        
    } else {
        fprintf(stderr, "[error] failed to disassemble code at address 0x%08x\n", (uint32_t)pc);
        return false;
        
    }
    
    return false;
    
#endif
    
    return false;
}

// executed if pcbOnBeforeInsnTranslate returns true
int pcbOnBeforeInsnExec(CPUState * cpu, target_ulong pc) {
    // does nothing
    return 0;
}

int handleAfterCall(CPUState* cpu, target_ulong pc, target_ulong caller) {
    
#if defined(TARGET_I386)
    
    if (!isRunningAnalysisHere(cpu, pc)) {
        return 0;
    }
    
    CPUArchState* arch = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
    
    // record return address
    target_ulong esp = arch->regs[R_ESP];

    // somehow, the pc is not the instr at the start of func. 
    // it seems, the execution has not been completed. so, better just mark
    // the call at afterInsn, and later, in onBeforeBasicBlockExec, just execute this code
    target_ulong ret_addr;
    if (-1 == panda_virtual_memory_read(cpu, esp, (uint8_t*) (&ret_addr), sizeof (ret_addr))) {
        fprintf(stderr, "[error] Unable to read stack address (0x%lx) for return value",
                (uint64_t) esp);
        return 0;
    }
    
    target_ulong tid = get_tid(cpu);
    fprintf(stderr, "[debug] thread %u, executing call from 0x%08x of function "
            "at address 0x%08x, returns in 0x%08x\n", 
            (uint32_t)tid, (uint32_t)caller, (uint32_t)pc, (uint32_t)ret_addr);
    
    if (tid > 0) {
        CALLSTACK& tidCS = tidCallStackMap[tid];
        CALLRETURN callRet;
        callRet.callAddr = pc;
        callRet.esp = esp;
        callRet.retAddr = ret_addr;
        callRet.caller = caller;
        callRet.memWriteMap.clear();
        tidCS.callStack.push(callRet);
        
    } else {
        fprintf(stderr, "[debug] invalid thread id 0, ignore\n");
        
    }
    
#endif
    
    return 0;
}

// executed if pcbOnAfterInsnTranslate returns true
int pcbOnAfterInsnExec(CPUState * cpu, target_ulong pc) {
    // after "call" is executed
    // check top of stack for return address
    
#if defined(TARGET_I386)
    
    if (!isRunningAnalysisHere(cpu, pc)) {
        return 0;
    }
    
    target_ulong tid = get_tid(cpu);
    fprintf(stderr, "[debug] thread %u, after execute call instruction at 0x%08x\n", 
            (uint32_t)tid, (uint32_t)pc);
    // mark tid for call next.
//    tidIsCallExecutedMap[tid] = true;
    tidIsCallExecutedMap[tid] = pc;
    
#endif
    return 0;
}

bool isPrintableAscii(uint32_t data) {
    return data >= 0x20 && data <= 0x7e;
}

typedef void (*extractorFn)(const uint8_t*, int, std::set<std::string>&);

void extractAsciiStrFromBuffer(const uint8_t* buf, int buflen, 
        std::set<std::string> &strSet) {
    
    std::stringstream ss;
    for (int i=0; i<buflen; ++i) {
        if (isPrintableAscii(buf[i])) {
            ss << (char)(buf[i]);
            
        } else {
            std::string use = ss.str();
            if (use != "") {
                strSet.insert(use);
            }
            ss.str("");
            
        }
    }
    
    std::string use = ss.str();
    if (use != "") {
        strSet.insert(use);
    }
    
}

void extractStr(const CALLRETURN& topReturn, extractorFn fn, 
        std::set<std::string>& setStr) {
    
    target_ulong nextAddr = 0;
    std::vector<uint8_t> tmpBuf;
    
    for (memWriteMapConstIt mwIt = topReturn.memWriteMap.begin();
            mwIt != topReturn.memWriteMap.end(); ++mwIt) {
        const MEMWRITERECORD& writeRecord = mwIt->second;
        if (nextAddr > 0 && nextAddr != writeRecord.writeAddr) {
            fn(&(tmpBuf[0]), tmpBuf.size(), setStr);
            tmpBuf.clear();
        }
        const uint8_t* pv = reinterpret_cast<const uint8_t*>(&(writeRecord.writeValue));
        for (int i=0; i<writeRecord.size; ++i) {
            tmpBuf.push_back(*(pv + i));
        }
        nextAddr = writeRecord.writeAddr + writeRecord.size;
    }
    // grab leftovers
    fn(&(tmpBuf[0]), tmpBuf.size(), setStr);
    
}

void extractAsciiStr(const CALLRETURN& topReturn) {
    extractStr(topReturn, extractAsciiStrFromBuffer, asciiSet);
}

void extractUtf16StrFromBuffer(const uint8_t* buf, int buflen, 
        std::set<std::string>& strSet) {
    
    std::stringstream ss;
    for (int i=0; i<buflen;) {
        if (isPrintableAscii(buf[i]) && i < buflen-1 && buf[i+1] == 0) {
            ss << (char)(buf[i] & 0xFF);
            i += 2;
            
        } else {
            std::string use = ss.str();
            if (use != "") {
                strSet.insert(use);
            }
            ss.str("");
            i ++;
            
        }
    }
    
    std::string use = ss.str();
    if (use != "") {
        strSet.insert(use);
    }
    
}

// only handle format \xZZ\x00 types.
void extractUtf16Str(const CALLRETURN& topReturn) {
    extractStr(topReturn, extractUtf16StrFromBuffer, utf16leSet);
}

int pcbOnBeforeBlockExec(CPUState * cpu, TranslationBlock * tb) {
    // check if first instruction is a return from a call.
#if defined(TARGET_I386)
    
    if (!isRunningAnalysisHere(cpu, tb->pc)) {
        return 0;
    }
    
    target_ulong tid = get_tid(cpu);
//    fprintf(stderr, "[debug] executing block at address 0x%08x, tid %u\n", (uint32_t)tb->pc, 
//            (uint32_t)tid);
    
    tidIsCallExecutedMapIt callExecIt = tidIsCallExecutedMap.find(tid);
    if (callExecIt != tidIsCallExecutedMap.end() && callExecIt->second != 0) {
        handleAfterCall(cpu, tb->pc, callExecIt->second);
        tidIsCallExecutedMap[tid] = 0;
    }
    
    if (tid == 0) {
        fprintf(stderr, "[debug] ignoring tid == 0\n");
        return 0;
    }
    
    CPUArchState* arch = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
    
    tidCallStackMapIt it = tidCallStackMap.find(tid);
    if (it != tidCallStackMap.end()) {
        CALLSTACK& tidCS = it->second;
        if (!tidCS.callStack.empty()) {
            // using pointer because if using reference, somehow, 
            // it is not updated when reassigned. Wonder why?
            CALLRETURN* pTopReturn = &(tidCS.callStack.top());
            RR_prog_point pp = rr_prog_point();
            
            target_ulong currentEsp = arch->regs[R_ESP];
            
            // while current esp less than esp at top of stack
            // means basic block is still executing in that function.
            // stack grows from high addr to low addr (inverse of heap)
            
            while (currentEsp > pTopReturn->esp) {
                
                CALLRETURN copiedTop = *pTopReturn;
                
                // improvement 1, do not print Empty blocks!!
                // improvement 2, also print the consecutive printable strings
                if (!pTopReturn->memWriteMap.empty()) {
                    fprintf(gOutputFile, "## Execution instrcnt=%lu tid=%u caller=0x%08x func=0x%08x ret=0x%08x\n",
                            (uint64_t)pp.guest_instr_count,
                            (uint32_t)tid,
                            (uint32_t)pTopReturn->caller,
                            (uint32_t)pTopReturn->callAddr, 
                            (uint32_t)pTopReturn->retAddr);
                    
                    std::stringstream ssv;
                    const uint8_t* pVal;
                    for (memWriteMapIt mwIt = pTopReturn->memWriteMap.begin();
                            mwIt != pTopReturn->memWriteMap.end(); ++mwIt) {
                        MEMWRITERECORD& writeRecord = mwIt->second;
                        
                        pVal = reinterpret_cast<const uint8_t*>(
                                &writeRecord.writeValue);
                        
                        ssv.str("");
                        for (int i=0; i<writeRecord.size; ++i) {
                            if (isPrintableAscii(*(pVal+i))) {
                                ssv << (char)(*(pVal+i));
                            } else {
                                ssv << ".";
                            }
                        }
                        fprintf(gOutputFile, "%lu %08x %08x %d %lx (%s)\n", 
                            (uint64_t)writeRecord.writeInstrCnt,
                            (uint32_t)writeRecord.writeInsnAddr, 
                            (uint32_t)writeRecord.writeAddr, 
                            (uint32_t)writeRecord.size, 
                            (uint64_t)writeRecord.writeValue,
                            ssv.str().c_str());
                    }
                    fprintf(gOutputFile, "\n");
                    
                    extractAsciiStr(*pTopReturn);
                    extractUtf16Str(*pTopReturn);
                    
                }
                
                tidCS.callStack.pop();
                if (tidCS.callStack.empty()) {
                    break;
                } else {
                    pTopReturn = &(tidCS.callStack.top());
                }
                
                // this is NOP if copiedTop memWriteMap is empty.
                for (memWriteMapIt mwIt = copiedTop.memWriteMap.begin();
                        mwIt != copiedTop.memWriteMap.end(); ++mwIt) {
                    // push write map from copiedTop, but if it already exist, 
                    // ignore them!
                    // if there exist writes in this block after the writes by
                    // the call, it should be overwritten by latest writes
                    // but, if this is immediately after return from call, there won't
                    // be any writes by the caller block! so, just overwrite them!
                    
                    bool overwrite = false;
                    memWriteMapIt inparent = pTopReturn->memWriteMap.find(
                            mwIt->first);
                    if (inparent == pTopReturn->memWriteMap.end()) {
                        overwrite = true;
                    } else {
                        const MEMWRITERECORD& writeParent = inparent->second;
                        const MEMWRITERECORD& writeCopied = mwIt->second;
                        if (writeParent.writeInstrCnt < writeCopied.writeInstrCnt) {
                            overwrite = true;
                        }
                    }
                    
                    if (overwrite) {
                        pTopReturn->memWriteMap[mwIt->first] = mwIt->second;
                    }
                    
                }
                
            }
            
        } else {
            fprintf(stderr, "[warn] stack for tid %u is empty\n", (uint32_t)tid);
            return 0;
        }
    } else {
        fprintf(stderr, "[warn] unable to find tid %u in call stack map\n", 
                (uint32_t)tid);
        return 0;
        
    }
    
#endif
    return 0;
}

bool init_plugin(void * self) {
    
#if defined(TARGET_I386)
    
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
    cs_option(gCapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(gCapstoneHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
    gCapstoneOpened = true;
    
    gStartAnalysisAddr = 0;
    gEndAnalysisAddr = 0x10000000;
    
    procFilterList.push_back(new ArithmeticFilter());
    procFilterList.push_back(new XorFilter());
    procFilterList.push_back(new MovFilter());
    procFilterList.push_back(new ShiftFilter());
    
    panda_cb pcb;
    
    pcb.after_block_translate = pcbAfterBlockTranslate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    
    pcb.before_block_exec = pcbOnBeforeBlockExec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    
    pcb.insn_translate = pcbOnBeforeInsnTranslate;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = pcbOnBeforeInsnExec;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    
    pcb.after_insn_translate = pcbOnAfterInsnTranslate;
    panda_register_callback(self, PANDA_CB_AFTER_INSN_TRANSLATE, pcb);
    pcb.after_insn_exec = pcbOnAfterInsnExec;
    panda_register_callback(self, PANDA_CB_AFTER_INSN_EXEC, pcb);
    
    pcb.virt_mem_before_write = pcbOnVirtMemWrite;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
    
    return true;
    
#endif
    
    return false;
    
}

void uninit_plugin(void * self) {
    // log asciiSet
    fprintf(gOutputFile, "## ASCII Strings\n");
    for (StringSetIterator it = asciiSet.begin(); it != asciiSet.end(); ++it) {
        fprintf(gOutputFile, "%s\n", it->c_str());
    }
    
    fprintf(gOutputFile, "## UTF-16 Strings\n");
    for (StringSetIterator it = utf16leSet.begin(); it != utf16leSet.end(); ++it) {
        fprintf(gOutputFile, "%s\n", it->c_str());
    }
    
    int size = procFilterList.size();
    for (int i=0; i<size; ++i) {
        delete procFilterList[i];
    }
    
    if (gOutputFile) {
        fclose(gOutputFile);
    }
    if (gCapstoneOpened) {
        cs_close(&gCapstoneHandle);
    }
}
