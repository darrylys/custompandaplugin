/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plugin_plugin.h"

#include "win7x86osi_types.h"
#include "win7x86trospection.h"
#include "dywin7x86sp1apilogger.h"

#include "winhelper.h"
#include "apihelper.h"
#include "apilogger.h"

#include <stdint.h>

#include <map>
#include <string>
#include <stack>

#define G_PLUGIN_NAME "dywin7x86sp1apilogger"

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
	
	#include "dywin7x86sp1apilogger_int_fns.h"
}

typedef struct _API_RET_PT {
    // return address after call is done, taken from top of stack (ESP)
    target_ulong ret_addr;

    // esp of the return address
    target_ulong esp;

    // base address of the module
    target_ulong base_addr;

    // thread id
    target_ulong tid;

    // dll name (file name only)
    std::string dll_name;

    // API name
    std::string func_name;
    
    // dll name (filename with directory)
    std::string dll_full_path;
    
    // parameters, but not yet used now
    uint8_t param[32][8];
} API_RET_PT;

typedef struct _WIN_PE {
    std::string name;
    std::string file;
    target_ulong baseAddr;

} WIN_PE;

typedef struct _MEM {
    // map (base_address_dll, WIN_PE object)
    std::map<target_ulong, WIN_PE> memmap;
    typedef std::map<target_ulong, WIN_PE>::iterator memmap_it;

    // map (thread id, stack). everytime api call is detected, push the return address
    // to stack. Everytime checking first instruction from basic block, check
    // the top of stack for address. if the same, pop the stack
    std::map < target_ulong, std::stack<API_RET_PT> > retmap;
    typedef std::map < target_ulong, std::stack<API_RET_PT> >::iterator retmap_it;

} MEM;

uint64_t gTargetAsid;
MEM gMem;
bool gLogApi;
FILE * gOutputFile;
FILE * gDebugFile;
bool gUseAsDB;

WIN_PE* get_win_pe(CPUState* cpu, MEM& mem, target_ulong base_dll) {
	MEM::memmap_it it = mem.memmap.find(base_dll);
	WIN_PE * pWinPE = NULL;

	if (it == mem.memmap.end()) {
#ifdef _DEBUG
		fprintf(gDebugFile, "base_dll (0x%08lx) not found!\n", (uint64_t) base_dll);
		fflush(gDebugFile);
#endif

		// not found

		// current problem: assert.
		// wintrospection has asserts, if defined NDEBUG, compile error
		// because the assert contains actual operation to be performed as well.
		//                    OsiProc * current = get_current_process(cpu);
		panda::win::OsiProc * current = panda::win::get_current_process(cpu);

		if (current) {
#ifdef _DEBUG
			fprintf(gDebugFile, " - current process name: %s\n", current->name);
			fflush(gDebugFile);
#endif
			//                    OsiModules *ms = get_libraries(cpu, current);
			panda::win::OsiModules * ms = panda::win::get_libraries(cpu, current);
			
#ifdef _DEBUG
			fprintf(gDebugFile, " - ms: %p\n", ms);
			fflush(gDebugFile);
#endif                  
			if (ms) {
				
#ifdef _DEBUG
				fprintf(gDebugFile, " - ms->num=%d\n", ms->num);
				fflush(gDebugFile);
				
				fprintf(gDebugFile, " - ms->module=%p\n", ms->module);
				fflush(gDebugFile);
#endif
				for (uint32_t i = 0; i < ms->num; i++) {
					
#ifdef _DEBUG                   
					/*target_ulong offset;
					char *file;
					target_ulong base;
					target_ulong size;
					 char *name;*/
					fprintf(gDebugFile, " ms module [%d]\n", i);
					fprintf(gDebugFile, "  ---- name: %s\n", ms->module[i].name);
					fprintf(gDebugFile, "  ---- offset: %lu\n", (uint64_t) ms->module[i].offset);
					fprintf(gDebugFile, "  ---- base: %lu\n", (uint64_t) ms->module[i].base);
					fprintf(gDebugFile, "  ---- size: %lu\n", (uint64_t) ms->module[i].size);
					fprintf(gDebugFile, "  ---- file: %s\n", ms->module[i].file);
#endif
					
					if (ms->module[i].base == base_dll) {
#ifdef _DEBUG
						fprintf(gDebugFile, "initializing WinPE\n");
						fflush(gDebugFile);
#endif
						WIN_PE * pTmp = &(mem.memmap[ms->module[i].base]);
						pTmp->baseAddr = base_dll;
						pTmp->file = ms->module[i].file;
						pTmp->name = ms->module[i].name;

						//pTmp->init(cpu, ms->module[i].base, ms->module[i].name,
						//        ms->module[i].file, g_export_dir);

						pWinPE = pTmp;
						break;
					}
				}
			}
			
#ifdef _DEBUG
			fprintf(gDebugFile, " - freeing modules\n");
			fflush(gDebugFile);
#endif

			panda::win::free_osimodules(ms);
			panda::win::free_osiproc(current);

			//                    free_osimodules(ms);
			//                    free_osiproc(current);
			
#ifdef _DEBUG
			fprintf(gDebugFile, " - freeing modules done\n");
			fflush(gDebugFile);
#endif
			

		}

	} else {
		// exist
		pWinPE = &(it->second);

	}
	
	return pWinPE;
}

/*
 * in syscall case, in particular, NtXXX family API, the call is kinda wacky
 * 
 * The problem is the KiFastSyscall and KiFastSyscallRet.
 * 
 * KiFastSyscall pushes address to stack as usual
 * The problem is KiFastSyscallRet, which is just 4 bytes away from KiFastSyscall
 * KiFastSyscallRet is exported by ntdll.dll, but, it does not push the return
 * address to stack. As a result, the same return address (with same esp, no less)
 * is pushed twice in stack. When return addr is checked, it only pops one.
 * 
 * As a result, the real return address of NtXXX API is not detected because
 * the address is right below the top addr.
 * 
 * To implement:
 * To fix this problem, 
 * 1. just push when a call, determined by dll export table.
 * 2. don't care whether it pushes or not
 * 3. at beginning of basic block, check ESP. Remove all stack entries
 *    which has ESP lower than current ESP, and dump them as RETURN, but return value N/A
 *    ESP grows from high address to low address. Higher or equal addresses are left alone.
 *    stack entries should have esp ordered from high to low.
 * 4. if the last stack entry that is removed in step 3 has pc == current.pc, get return value
 *    from EAX, and dump it.
 * 
 */
int before_block_exec(CPUState *cpu, TranslationBlock *tb) {
#if defined(TARGET_I386)

    target_ulong asid = panda_current_asid(cpu);
    CPUArchState * arch = reinterpret_cast<CPUArchState*> (cpu->env_ptr);

    if (asid == gTargetAsid) {
        target_ulong pc = tb->pc;

        // change this to in_kernelspace function in callstack_instr
        if (!panda_in_kernel(cpu) && pc < (uint64_t) 0x80000000) { // comparison p >= 0 is always true

#ifdef _DEBUG
            RR_prog_point pp = rr_prog_point();
#endif
            MEM &mem = gMem;

            // PID and TID can be obtained from fs+0x20 and fs+0x24 respectively
            //target_ulong fs_pid = panda::win::get_pid(cpu);
            target_ulong fs_tid = panda::win::get_tid(cpu);
            //            assert(fs_tid == 0);

            // ignore if fs_tid == 0
            if (fs_tid == 0) {
                return 0;
            }

            // check return address
            MEM::retmap_it rit = mem.retmap.find(fs_tid);
            if (rit != mem.retmap.end() && !rit->second.empty()) {

                API_RET_PT *pRetPt = &(rit->second.top());

                target_ulong pc_esp = arch->regs[R_ESP];

#ifdef _DEBUG
                fprintf(gDebugFile, " - pc_esp: 0x%lx\n", (uint64_t) pc_esp);
                fflush(gDebugFile);
#endif

                // if the top of stack has esp higher than current esp, that means 
                // the function has no yet cleared it's stack --> not yet return
                if (pRetPt->esp < pc_esp) {

                    API_RET_PT retPtBeforeLast = rit->second.top();

                    // step 3
                    while (pRetPt->esp < pc_esp) {

#ifdef _DEBUG
                        fprintf(gDebugFile, " - remove entry in stack! TOP: {pRetPt->esp: 0x%lx, ret_addr: 0x%lx}\n",
                                (uint64_t) pRetPt->esp, (uint64_t) pRetPt->ret_addr);
                        fflush(gDebugFile);
#endif

#ifdef _DEBUG
                        fprintf(gDebugFile, "<<\t%lu\t0x%lx\t%ld\t0x%lx\t%s!%s\t0x%lx\tN/A\n",
                                (uint64_t) pp.guest_instr_count,
                                (uint64_t) asid, (uint64_t) fs_tid, (uint64_t) pc,
                                pRetPt->dll_name.c_str(), pRetPt->func_name.c_str(),
                                (uint64_t) pRetPt->ret_addr);
                        fflush(gDebugFile);
#endif


                        retPtBeforeLast = rit->second.top();

                        rit->second.pop();
                        if (rit->second.empty()) {
                            mem.retmap.erase(rit);
                            break;
                        } else {
                            pRetPt = &(rit->second.top());
                        }
                    }

#ifdef _DEBUG
                    fprintf(gDebugFile, " - current top entry: {pRetPt->ret_addr: 0x%lx, pRetPt->esp: 0x%lx}\n",
                            (uint64_t) pRetPt->ret_addr, (uint64_t) pRetPt->esp);
                    fflush(gDebugFile);
#endif

                    // step 3
                    // grab the final pRetPt before removed from stack
                    if (retPtBeforeLast.ret_addr == pc) {
                        // get returns
#ifdef _DEBUG
                        target_ulong retval = arch->regs[R_EAX];
#endif

                        // grab the parameters also, and the return values.

                        // TODO: run return callback
                        //PPP_RUN_CB(on_apireturn, cpu, pc, retPtBeforeLast.dll_name.c_str(), retPtBeforeLast.func_name.c_str());

                        if (gLogApi) {
                            std::string jsonLog;
                            
                            // dll_name is not needed here
                            // as the data is carried over from apilogger_log_call invocation previously
                            apilogger_log_return(cpu, pc, retPtBeforeLast.dll_name.c_str(),
                                    retPtBeforeLast.base_addr, retPtBeforeLast.func_name.c_str(), jsonLog);
                            fprintf(gOutputFile, "%s,\n", jsonLog.c_str());
                        }

#ifdef _DEBUG
                        fprintf(gDebugFile, "<<\t%lu\t0x%lx\t%ld\t0x%lx\t%s!%s\t0x%lx\n",
                                (uint64_t) pp.guest_instr_count,
                                (uint64_t) asid, (uint64_t) retPtBeforeLast.tid, (uint64_t) pc,
                                retPtBeforeLast.dll_name.c_str(), retPtBeforeLast.func_name.c_str(),
                                (uint64_t) retval);
                        fflush(gDebugFile);
#endif
                    }
#ifdef _DEBUG
                    else {
                        fprintf(gDebugFile, " - pc =/= ret_addr, pc: 0x%lx\n", (uint64_t) pc);
                        fflush(gDebugFile);
                    }
#endif          
                }
            }

            // this one is too slow!
            // searches for 40MB in memory (per 4KB) costs 10240 iterations!
            target_ulong base_dll = panda::win::find_image_base_addr(cpu, pc);

            if (base_dll) {
				
                MEM::memmap_it it = mem.memmap.find(base_dll);
                //WIN_PE * pWinPE = get_win_pe(cpu, mem, base_dll);
				WIN_PE * pWinPE = NULL;

                if (it == mem.memmap.end()) {
#ifdef _DEBUG
                    fprintf(gDebugFile, "base_dll (0x%08lx) not found!\n", (uint64_t) base_dll);
                    fflush(gDebugFile);
#endif

                    // not found

                    // current problem: assert.
                    // wintrospection has asserts, if defined NDEBUG, compile error
                    // because the assert contains actual operation to be performed as well.
                    //                    OsiProc * current = get_current_process(cpu);
                    panda::win::OsiProc * current = panda::win::get_current_process(cpu);

                    if (current) {
#ifdef _DEBUG
                        fprintf(gDebugFile, " - current process name: %s\n", current->name);
                        fflush(gDebugFile);
#endif
                        //                    OsiModules *ms = get_libraries(cpu, current);
                        panda::win::OsiModules * ms = panda::win::get_libraries(cpu, current);
                        
#ifdef _DEBUG
                        fprintf(gDebugFile, " - ms: %p\n", ms);
                        fflush(gDebugFile);
#endif                  
                        if (ms) {
                            
#ifdef _DEBUG
                            fprintf(gDebugFile, " - ms->num=%d\n", ms->num);
                            fflush(gDebugFile);
                            
                            fprintf(gDebugFile, " - ms->module=%p\n", ms->module);
                            fflush(gDebugFile);
#endif
                            for (uint32_t i = 0; i < ms->num; i++) {
                                
#ifdef _DEBUG                   
                                /*target_ulong offset;
                                char *file;
                                target_ulong base;
                                target_ulong size;
                                 char *name;*/
                                fprintf(gDebugFile, " ms module [%d]\n", i);
                                fprintf(gDebugFile, "  ---- name: %s\n", ms->module[i].name);
                                fprintf(gDebugFile, "  ---- offset: %lu\n", (uint64_t) ms->module[i].offset);
                                fprintf(gDebugFile, "  ---- base: %lu\n", (uint64_t) ms->module[i].base);
                                fprintf(gDebugFile, "  ---- size: %lu\n", (uint64_t) ms->module[i].size);
                                fprintf(gDebugFile, "  ---- file: %s\n", ms->module[i].file);
#endif
                                
                                if (ms->module[i].base == base_dll) {
#ifdef _DEBUG
                                    fprintf(gDebugFile, "initializing WinPE\n");
                                    fflush(gDebugFile);
#endif
                                    WIN_PE * pTmp = &(mem.memmap[ms->module[i].base]);
                                    pTmp->baseAddr = base_dll;
                                    pTmp->file = ms->module[i].file;
                                    pTmp->name = ms->module[i].name;

                                    //pTmp->init(cpu, ms->module[i].base, ms->module[i].name,
                                    //        ms->module[i].file, g_export_dir);

                                    pWinPE = pTmp;
                                    break;
                                }
                            }
                        }
                        
#ifdef _DEBUG
                        fprintf(gDebugFile, " - freeing modules\n");
                        fflush(gDebugFile);
#endif

                        panda::win::free_osimodules(ms);
                        panda::win::free_osiproc(current);

                        //                    free_osimodules(ms);
                        //                    free_osiproc(current);
                        
#ifdef _DEBUG
                        fprintf(gDebugFile, " - freeing modules done\n");
                        fflush(gDebugFile);
#endif
                        

                    }

                } else {
                    // exist
                    pWinPE = &(it->second);

                }

                if (pWinPE) {

                    const char * api_name = apilogger_find_func(cpu,
                            pWinPE->name.c_str(), pc, pWinPE->baseAddr);

                    if (api_name != NULL) {

                        // record return address
                        target_ulong esp = arch->regs[R_ESP];

                        target_ulong ret_addr;
                        if (-1 == panda_virtual_memory_read(cpu, esp, (uint8_t*) (&ret_addr), sizeof (ret_addr))) {
                            fprintf(gDebugFile, " - [ERROR] unable to read stack address (0x%lx) for return value",
                                    (uint64_t) esp);
                            fflush(gDebugFile);
                            return 0;
                        }

                        // TODO: call API here:
                        // add function parameters also.
                        // PPP_RUN_CB(on_apicall, cpu, pc, pWinPE->get_file_name(), api_name);
                        if (gLogApi) {
                            std::string jsonLog;
                            
                            // using pWinPE->name instead of file, because name only contains the dll name
                            // while file contains the absolute path of the dll.
                            // the database csv file currently only contain the dll name only.
                            apilogger_log_call(cpu, pc, pWinPE->name.c_str(), pWinPE->baseAddr, api_name, jsonLog);
                            fprintf(gOutputFile, "%s,\n", jsonLog.c_str());
                        }
#ifdef _DEBUG
                        fprintf(gDebugFile, ">>\t%lu\t0x%lx\t%ld\t0x%lx\t%s!%s\t0x%lx\n",
                                (uint64_t) pp.guest_instr_count,
                                (uint64_t) asid, (uint64_t) fs_tid, (uint64_t) pc,
                                pWinPE->file.c_str(), api_name, (uint64_t) ret_addr);
                        fflush(gDebugFile);
#endif

                        // normal situation
                        API_RET_PT pt;
                        pt.base_addr = base_dll;
                        pt.dll_name = pWinPE->name;
                        pt.dll_full_path = pWinPE->file;
                        pt.func_name = api_name;
                        pt.ret_addr = ret_addr;
                        pt.tid = fs_tid;

                        // prev_esp is wrong.
                        // I forget about the callee cleaning up the stack thing!
                        // cannot use esp at all now!
                        pt.esp = esp;
                        // pt.params later!

                        std::stack<API_RET_PT> &apicallstack = mem.retmap[fs_tid];
                        apicallstack.push(pt);
                    }
                }
            }
        }
    }

#endif

    return 0;
}

bool init_plugin(void * self) {

#ifdef _DEBUG
    printf(">> init_plugin()\n");
#endif
    
    assert(panda_os_familyno == OS_WINDOWS);
    assert(panda_os_bits == 32);
    assert(0 == strcmp(panda_os_variant, "7"));

#if defined TARGET_I386

    panda_enable_precise_pc();
    panda_enable_memcb();

    //    panda_require("osi");
    //    if (!init_osi_api()) {
    //        return false;
    //    }

    panda_arg_list *args = panda_get_args(G_PLUGIN_NAME);
	
	gUseAsDB = panda_parse_bool_opt(args, "use_as_db", "set to true if this "
			"plugin is used as API database only, no monitoring");
	
	printf("Used as DB? %d\n", gUseAsDB);
	
	if (!gUseAsDB) {
		const char * str_asid = panda_parse_string(args, "asid", NULL);
		if (!str_asid) {
			printf("unable to proceed, give asid for monitoring using asid parameter! asid is hex string\n");
			return false;
		}
#ifdef _DEBUG
		printf(" - str_asid: %s\n", str_asid);
#endif
		
		::sscanf(str_asid, "%lx", &gTargetAsid);
		
	} else {
		gTargetAsid = 0;
		
	}

    const char * fname_func_csv = panda_parse_string(args, "apicsv", NULL);
    if (!fname_func_csv) {
        printf("Provide the api.csv file\n");
        return false;
    }

    const char * fname_types_csv = panda_parse_string(args, "typecsv", NULL);
    if (!fname_types_csv) {
        printf("Provide the type.csv file\n");
        return false;
    }

    gDebugFile = fopen(G_PLUGIN_NAME"-debug.log", "w");
    if (!gDebugFile) {
        return false;
    }

    gOutputFile = fopen(G_PLUGIN_NAME"-apis.log", "w");
    if (!gOutputFile) {
        return false;
    }
	
	if (!gUseAsDB) {
		gLogApi = panda_parse_bool_opt(args, "log_api_call", "Should log the api calls?");
	} else {
		gLogApi = false;
	}

#ifdef _DEBUG
    printf(" - initializing apilogger\n");
#endif
    
    if (!apilogger_init(fname_types_csv, fname_func_csv)) {
        printf("Initializing api logger failed, check if these files exist "
                "and should be absolute paths : [%s], [%s]\n",
                fname_types_csv, fname_func_csv);
        return false;
    }
    
#ifdef _DEBUG
    printf(" - initializing panda::win::init_system()\n");
#endif

    if (!panda::win::init_system()) {
        printf("Initializing win7x86trospection failed\n");
        return false;
    }
	
	if (!gUseAsDB) {
		panda_cb pcb;

		pcb.before_block_exec = before_block_exec;
		panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	} else {
		printf("Panda callbacks are not registered because the plugin will be used as API DB only!\n");
	}

#ifdef _DEBUG
    printf(" - panda_free_args\n");
#endif
    
    panda_free_args(args);

    if (gLogApi) {
        fprintf(gOutputFile, "[\n");
    }
    
#ifdef _DEBUG
    printf("<< init_plugin()\n");
#endif

    return true;

#endif    
    return false;

}

void uninit_plugin(void * self) {

    if (gLogApi) {
        // {} is a sentinel object
        fprintf(gOutputFile, "{}]\n");
    }

    apilogger_close();

    if (gDebugFile) {
        fclose(gDebugFile);
    }

    if (gOutputFile) {
        fclose(gOutputFile);
    }

}

/**
 * Reads the value of the parameter at given offset from stack when function call is invoked.
 * offset starts from 0 (automatically skipping return address in stack), 
 * but it has to be added manually by the caller.
 * This is very compiler implementation specific. In most cases, Windows API, the offset is 
 * always incremented by pointer size (4 bytes for x86, 8 bytes for x64)
 *
 * The difference is when an object is passed by value, but this does not exist in Windows API.
 * 
 * @param cpu
 * @param offset, the offset in bytes from ESP + return address to be read
 * @param buf, out buffer
 * @param bufsize, size of out buffer.
 * @return 1 if success, 0 if failed.
 */
int get_func_param(CPUState *cpu, target_ulong offset, void * buf, int bufsize) {

#if defined(TARGET_I386)
    CPUArchState * arch = reinterpret_cast<CPUArchState*> (cpu->env_ptr);
    int size = sizeof (target_ulong);
    if (-1 == panda_virtual_memory_read(
            cpu,
            arch->regs[R_ESP] + size + offset, // skip return address
            (uint8_t*) (buf), bufsize)) {

        return 0;

    }

    return 1;
#endif

    return 0;

}

/**
 * This is halfway from get_func_param above. If get_func_param reads the value of the offset,
 * this one simply returns the virtual address of the offset.
 *
 * @param cpu
 * @param offset
 * @return Virtual Address of given offset from ESP + return address
 */
target_ulong get_func_param_addr(CPUState *cpu, target_ulong offset) {

#if defined(TARGET_I386)
    CPUArchState * arch = reinterpret_cast<CPUArchState*> (cpu->env_ptr);
    int size = sizeof (target_ulong);

    return arch->regs[R_ESP] + size + offset;

#endif

    return 0;

}

int get_api_info(CPUState* cpu, target_ulong pc, API_INFO* api_info) {
	
	#if defined(TARGET_I386)
	
	if (api_info == NULL) {
		return E_W_ERR;
	}
	
	panda::win::OsiProc* p_current_proc = panda::win::get_current_process(cpu);
	if (p_current_proc == NULL) {
		return E_W_ERR;
	}
	
	bool found = false;
	
	panda::win::OsiModules * p_ms = panda::win::get_libraries(cpu, p_current_proc);
	if (p_ms != NULL) {
		
		for (int i = 0; i < p_ms->num; ++i) {
			panda::win::OsiModule& module = p_ms->module[i];
			if (pc >= module.base && pc < module.base + module.size) {
				// found location of pc
				
				const char * apiname = apilogger_find_func(cpu, module.name, pc, module.base);
				if (apiname != NULL) {
					
					//typedef struct _API_INFO {
					//	std::string fn_name;
					//std::string module_name;
					//std::string module_file;
					//target_ulong module_base;
					//target_ulong fn_rva;
					//target_ulong offset;
					//	
					//} API_INFO;
					
					api_info->fn_name = apiname;
					found = true;
					
				} else {
					// better also add some info if false.
					// this allows for more logging info to callers.
					api_info->fn_name = ""; // fn_name is string.
					found = false;
					
				}
				
				// since these are just dll info, it does not depend on api name at any level.
				api_info->module_name = module.name;
				api_info->module_file = module.file;
				api_info->module_base = module.base;
				api_info->fn_rva = pc - module.base;
				api_info->offset = module.offset;
				api_info->module_size = module.size;
				
				break;
			}
		}
		
		panda::win::free_osimodules(p_ms);
		p_ms = NULL;
	}
	
	panda::win::free_osiproc(p_current_proc);
	p_current_proc = NULL;
	
	if (found) {
		return S_W_OK;
	} else {
		return E_W_ERR;
	}
	
	#endif
	
	return E_W_ERR;
}
