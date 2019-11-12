/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

//#include "windefs.h"
#include "winhelper.h"

#include <string>
//#include "elapsed.h"

using std::string;

extern FILE * gDebugFile;

namespace panda {
    namespace win {

        typedef target_ulong ptr_t;

        //        
        //        ptr_t get_dtb(CPUState *env, ptr_t eproc) {
        //            ptr_t dtb;
        //            panda_virtual_memory_rw(env, eproc+EPROC_DTB_OFF, (uint8_t *)&dtb, sizeof(ptr_t), false);
        //            return dtb;
        //        }
        //        
        //        bool is_valid_process(CPUState *env, ptr_t eproc) {
        //            uint8_t type;
        //            uint8_t size;
        //
        //            panda_virtual_memory_rw(env, eproc+EPROC_TYPE_OFF, (uint8_t *)&type, 1, false);
        //            panda_virtual_memory_rw(env, eproc+EPROC_SIZE_OFF, (uint8_t *)&size, 1, false);
        //
        //            return (type == EPROC_TYPE && size == EPROC_SIZE);
        //        }
        //        
        //        ptr_t get_pid(CPUState *env, ptr_t eproc) {
        //            ptr_t pid;
        //            panda_virtual_memory_rw(env, eproc+EPROC_PID_OFF, (uint8_t *)&pid, sizeof(ptr_t), false);
        //            return pid;
        //        }
        //
        //        ptr_t get_ppid(CPUState *env, ptr_t eproc) {
        //            ptr_t ppid;
        //            panda_virtual_memory_rw(env, eproc+EPROC_PPID_OFF, (uint8_t *)&ppid, sizeof(ptr_t), false);
        //            return ppid;
        //        }
        //
        //        ptr_t get_peb(CPUState *env, ptr_t eproc) {
        //            ptr_t peb = 0;
        //            panda_virtual_memory_rw(env, eproc+EPROC_PEB_OFF, (uint8_t *)&peb, sizeof(ptr_t), false);
        //            return peb;
        //        }
        //
        //        // *must* be called on a buffer of size 16 or greater
        //        void get_procname(CPUState *env, ptr_t eproc, char *name) {
        //            panda_virtual_memory_rw(env, eproc+EPROC_NAME_OFF, (uint8_t *)name, 15, false);
        //            name[15] = '\0';
        //        }
        //        
        //        ptr_t get_next_proc(CPUState *env, ptr_t eproc) {
        //            ptr_t next;
        //            if (-1 == panda_virtual_memory_rw(env, eproc+EPROC_LINKS_FLINK_OFF, (uint8_t *)&next, sizeof(ptr_t), false)) 
        //                return 0;
        //            next -= EPROC_LINKS_FLINK_OFF;
        //            return next;
        //        }
        //
        //        ptr_t get_prev_proc(CPUState *env, ptr_t eproc) {
        //            ptr_t next;
        //            if (-1 == panda_virtual_memory_rw(env, eproc+EPROC_LINKS_BLINK_OFF, (uint8_t *)&next, sizeof(ptr_t), false)) 
        //                return 0;
        //            next -= EPROC_LINKS_BLINK_OFF;
        //            return next;
        //        }
        //
        //        ptr_t get_kpcr(CPUState *env) {
        //        #if defined(TARGET_I386)
        //                CPUArchState *arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
        //            return arch->segs[R_FS].base;
        //        #endif
        //                return 0;
        //        }
        //
        //        ptr_t get_current_proc(CPUState *env, ptr_t kpcr) {
        //
        //            ptr_t thread, proc, fs_base;
        //            
        //            if (kpcr == 0) {
        //                kpcr = get_kpcr(env);
        //            }
        //            fs_base = kpcr; 
        //
        //            // Read KPCR->CurrentThread->Process
        //            panda_virtual_memory_rw(env, fs_base+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, sizeof(ptr_t), false);
        //            panda_virtual_memory_rw(env, thread+ETHREAD_EPROC_OFF, (uint8_t *)&proc, sizeof(ptr_t), false);
        //
        //            return proc;
        //        }
        //        
        //        
        //        void fill_OsiProcess(CPUState *env, ptr_t eproc, OsiProcess &out) {
        //            //memset(&out, 0, sizeof(OsiProcess));
        //            
        //            pid_t pid = get_pid(env, eproc);
        //            pid_t ppid = get_ppid(env, eproc);
        //
        //            char name[16];
        //            get_procname(env, eproc, name);
        //
        //            ptr_t asid = get_dtb(env, eproc);
        //
        //            out.asid = asid;
        //            out.eproc = eproc;
        //            out.pid = pid;
        //            out.ppid = ppid;
        //            out.imageName = string(name);
        //        }
        //        
        //        bool get_val(CPUState *env, ptr_t base, ptr_t off, uint32_t size, uint8_t *out) {
        //    
        //            if (-1 == panda_virtual_memory_read(env, base+off, out, size)) {
        //                return false;
        //            }
        //            return true;
        //
        //        }
        //        
        // this returns 0x804d7000 as well
        // according to uninformed.org in finding ntoskrnl.exe base, this result matches
        // with Windows XP SP2 / SP3. This seems promising!
        // next step is to create a Windows PE header parser to find the Export table!
        //        ptr_t find_ntoskrnl_base_addr_via_idlethread(CPUState *env) {
        //#if defined(TARGET_I386)
        //
        //            ptr_t kpcr = panda::win::get_kpcr(env);
        //            ptr_t idle_addr;
        //            if (-1 == panda_virtual_memory_read(env, kpcr + KPCR_IDLETHRAD_OFF, 
        //                    (uint8_t*)&idle_addr, sizeof(idle_addr))) {
        //                return 0;
        //            }
        //
        //            return find_image_base_addr(env, idle_addr);
        //
        //#elif defined (TARGET_X86_64)
        //            return 0;
        //
        //#elif defined (TARGET_ARM)
        //            return 0;
        //
        //#else
        //#error "Unsupported Architecture!"
        //#endif
        //
        //            return 0;
        //        }

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

        /**
         * Finds image base address from given starting address. This algorithm uses
         * scan down technique, which basically reads the address from beginning of the page
         * where starting address resides and brute force search this and preceding pages for
         * MZ magic PE header.
         *
         * On average, this usually consumes around ~30ms, if found. But, if the MZ magic header is not
         * found, it wasted ~500ms
         * 
         * Only tested on Windows 7 x86 SP1.
         */
        ptr_t find_image_base_addr(CPUState *env, ptr_t start_search) {

            //Timer t;
            //t.start();

#if defined(TARGET_I386)
            ptr_t start = (ptr_t) (start_search & 0xFFFFF000);

#elif defined(TARGET_X86_64)
            ptr_t start = (ptr_t) (start_search & 0xFFFFFFFFFFFFF000LL);

#elif defined(TARGET_ARM)
            return 0;
#endif


#if defined(TARGET_I386) || defined(TARGET_X86_64)

            // in volatility, the search is 5 MB. Since disk block size is 512 byte 
            // and memory block is 4KB
            // we try to multiply the search by 8.
            for (unsigned int i = 0; i < 40 * 1024 * 1024 && start > i; i += 0x1000) {
                uint16_t word;
                if (-1 == panda_virtual_memory_read(env, start - i, (uint8_t*) & word,
                        sizeof (word))) {
                    continue;
                }

                // MZ signature ('ZM' for Little Endian)
                if (word == 0x5a4d) {
                    //fprintf(debug_file, " - elapsed: %.6lf\n", t.end());
                    return start - i;
                }
            }

            //return 0;

#endif

            //fprintf(debug_file, " - elapsed: %.6lf\n", t.end());

            return 0;
        }

        /**
         * Reads zero-terminated wide string (UTF-16LE) from guest
         */
        uint32_t guest_wzstrncpy(CPUState *cpu, uint16_t *buf, size_t maxlen, target_ulong guest_addr) {
            buf[0] = 0;
            unsigned i = 0;
            for (i = 0; i < maxlen; i++) {
                panda_virtual_memory_rw(cpu, guest_addr + sizeof (buf[0]) * i, (uint8_t *) & buf[i], sizeof (buf[0]), 0);
                if (buf[i] == 0) {
                    break;
                }
            }
            buf[maxlen - 1] = 0;
            return i;
        }

        /**
         * Reads zero-terminated ascii-string from guest
         */
        uint32_t guest_zstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
            buf[0] = 0;
            unsigned i = 0;
            for (i = 0; i < maxlen; i++) {
                panda_virtual_memory_rw(cpu, guest_addr + sizeof (buf[0]) * i, (uint8_t *) & buf[i], sizeof (buf[0]), 0);
                if (buf[i] == 0) {
                    break;
                }
            }
            buf[maxlen - 1] = 0;
            return i;
        }
        
        /**
         * Reads possibly non zero-terminated wide (2 byte) character string from guest.
         * @param cpu
         * @param buf must contain minimum nRead+1 number of characters
         * @param nRead is number of characters read
         * @param guest_addr
         * @return 
         */
        uint32_t guest_wbstrncpy(CPUState *cpu, uint16_t *buf, int nRead, target_ulong guest_addr) {
            buf[0] = 0;
            unsigned i = 0;
            for (i = 0; i < nRead; i++) {
                panda_virtual_memory_rw(cpu, guest_addr + sizeof (buf[0]) * i, (uint8_t *) & buf[i], sizeof (buf[0]), 0);
                if (buf[i] == 0) {
                    break;
                }
            }
            buf[nRead] = 0;
            return i;
        }
        
        /**
         * Reads possibly non zero-terminated single byte character string from guest
         * @param cpu
         * @param buf must contain minimum nRead+1 number of characters
         * @param nRead is number of characters read. 
         * @param guest_addr
         * @return 
         */
        uint32_t guest_bstrncpy(CPUState *cpu, char *buf, int nRead, target_ulong guest_addr) {
            buf[0] = 0;
            unsigned i = 0;
            for (i = 0; i < nRead; i++) {
                panda_virtual_memory_rw(cpu, guest_addr + sizeof (buf[0]) * i, (uint8_t *) & buf[i], sizeof (buf[0]), 0);
                if (buf[i] == 0) {
                    break;
                }
            }
            buf[nRead] = 0;
            return i;
        }
    }
}
