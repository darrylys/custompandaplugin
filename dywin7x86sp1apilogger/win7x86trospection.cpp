/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * The scripts here are ripped off from wintrospection.cpp and win7x86intro.cpp from PANDA
 * plugins. It is moved here because PANDA has some asserts in wintrospection and win7x86intro when
 * reading dtb value and some other place which simply kills the qemu process, instead of returning error.
 */
 
#include "win7x86trospection.h"

#include <glib.h>
#include <cstdio>

#if defined(TARGET_I386)
#define KPCR_CURTHREAD_OFF   0x124 // _KPCR.PrcbData.CurrentThread
#define EPROC_DTB_OFF        0x018 // _EPROCESS.Pcb.DirectoryTableBase
#define EPROC_TYPE_OFF       0x000 // _EPROCESS.Pcb.Header.Type
#define EPROC_SIZE_OFF       0x002 // _EPROCESS.Pcb.Header.Size
#define EPROC_TYPE           0x003 // Value of Type
#define LDR_LOAD_LINKS_OFF   0x000 // _LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
#define LDR_BASE_OFF         0x018 // _LDR_DATA_TABLE_ENTRY.DllBase
#define LDR_SIZE_OFF         0x020 // _LDR_DATA_TABLE_ENTRY.SizeOfImage
#define LDR_BASENAME_OFF     0x02c // _LDR_DATA_TABLE_ENTRY.BaseDllName
#define LDR_FILENAME_OFF     0x024 // _LDR_DATA_TABLE_ENTRY.FullDllName
#define OBJNAME_OFF          0x008
#define FILE_OBJECT_NAME_OFF 0x030
#define FILE_OBJECT_POS_OFF  0x038

static uint32_t kthread_kproc_off;  // _KTHREAD.Process
static uint32_t eproc_pid_off;      // _EPROCESS.UniqueProcessId
static uint32_t eproc_ppid_off;     // _EPROCESS.InheritedFromUniqueProcessId
static uint32_t eproc_name_off;     // _EPROCESS.ImageFileName
static uint32_t eproc_objtable_off; // _EPROCESS.ObjectTable
static uint32_t eproc_size;         // Value of Size
static uint32_t eproc_links_off;    // _EPROCESS.ActiveProcessLinks
static uint32_t obj_type_file;      // FILE object type
static uint32_t obj_type_key;       // KEY object type
static uint32_t obj_type_process;   // PROCESS object type
static uint32_t obj_type_offset;    // XXX_OBJECT.Type (offset from start of OBJECT_TYPE_HEADER)
static uint32_t ntreadfile_esp_off; // Number of bytes left on stack when NtReadFile returns

#define KMODE_FS               0x030 // Segment number of FS in kernel mode
#define KPCR_KDVERSION_OFF     0x034  // _KPCR.KdVersionBlock
#define KDVERSION_DDL_OFF      0x020  // _DBGKD_GET_VERSION64.DebuggerDataList
#define KDBG_PSLML             0x048  // _KDDEBUGGER_DATA64.PsLoadedModuleList
#define EPROC_PEB_OFF          0x1a8 // _EPROCESS.Peb
#define PEB_LDR_OFF            0x00c // _PEB.Ldr
#define PEB_LDR_MEM_LINKS_OFF  0x014 // _PEB_LDR_DATA.InMemoryOrderModuleLinks
#define PEB_LDR_LOAD_LINKS_OFF 0x00c // _PEB_LDR_DATA.InMemoryOrderModuleLinks
#define LDR_LOAD_LINKS_OFF     0x000 // _LDR_DATA_TABLE_ENTRY.InLoadOrderLinks

#define PTR uint32_t

// Function pointer, returns location of KPCR structure.  OS-specific.
static PTR(*get_kpcr)(CPUState *cpu);
#endif

extern FILE * gDebugFile;

namespace panda {
    namespace win {
        namespace x86sp1 {
            
            void fill_osimod(CPUState *cpu, OsiModule *m, PTR mod, bool ignore_basename);
            void fill_osiproc(CPUState *cpu, OsiProc *p, PTR eproc);
            char *get_unicode_str(CPUState *cpu, PTR ustr);
            uint32_t get_current_proc(CPUState *cpu);
            
            PTR get_win7_kpcr(CPUState *cpu) {
#if defined(TARGET_I386)
                // Read the kernel-mode FS segment base
                uint32_t e1, e2;
                PTR fs_base;

                CPUArchState *env = (CPUArchState *)cpu->env_ptr;
                // Read out the two 32-bit ints that make up a segment descriptor
                panda_virtual_memory_rw(cpu, env->gdt.base + KMODE_FS, (uint8_t *)&e1, sizeof(PTR), false);
                panda_virtual_memory_rw(cpu, env->gdt.base + KMODE_FS + 4, (uint8_t *)&e2, sizeof(PTR), false);

                // Turn wacky segment into base
                fs_base = (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000);

                return fs_base;
#endif
                return 0;
            }
            
#if defined(TARGET_I386)
            uint32_t get_ntreadfile_esp_off(void) { return ntreadfile_esp_off; }
            uint32_t get_kthread_kproc_off(void) { return kthread_kproc_off; }
            uint32_t get_eproc_pid_off(void) { return eproc_pid_off; }
            uint32_t get_eproc_name_off(void) { return eproc_name_off; }
            uint32_t get_eproc_objtable_off(void) { return eproc_objtable_off; }
            uint32_t get_obj_type_offset(void) { return obj_type_offset; }
#endif
            
            bool init_system() {
#if defined(TARGET_I386)
                assert(panda_os_familyno == OS_WINDOWS);
                assert(panda_os_bits == 32);
                assert(0 == strcmp(panda_os_variant, "7"));
                
                kthread_kproc_off=0x150;
                eproc_pid_off=0x0b4;
                eproc_ppid_off=0x140;
                eproc_name_off=0x16c;
                eproc_objtable_off=0xf4;
                obj_type_file = 28;
                obj_type_key = 35;
                obj_type_process = 7;
                obj_type_offset = 0xc;
                eproc_size = 0x26;
                eproc_links_off = 0x0b8;
                ntreadfile_esp_off = 0;
                //panda_require("win7x86intro");
                //assert(init_win7x86intro_api());
                get_kpcr = get_win7_kpcr;
//                get_handle_object = get_win7_handle_object;
                return true;
#endif
                return false;
            }
            
            // Process introspection
            PTR get_next_proc(CPUState *cpu, PTR eproc) {
#if defined(TARGET_I386)
                PTR next;
                if (-1 == panda_virtual_memory_rw(cpu, eproc+eproc_links_off, (uint8_t *)&next, sizeof(PTR), false))
                    return 0;
                next -= eproc_links_off;
                return next;
#endif
                return 0;
            }
            
            bool is_valid_process(CPUState *cpu, PTR eproc) {
#if defined(TARGET_I386)
                uint8_t type;
                uint8_t size;

                if(eproc == 0) return false;

                if(-1 == panda_virtual_memory_rw(cpu, eproc+EPROC_TYPE_OFF, (uint8_t *)&type, 1, false)) return false;
                if(-1 == panda_virtual_memory_rw(cpu, eproc+EPROC_SIZE_OFF, (uint8_t *)&size, 1, false)) return false;

                return type == EPROC_TYPE && size == eproc_size &&
                    get_next_proc(cpu, eproc);
#endif
                return false;
            }
            
            uint32_t get_pid(CPUState *cpu, uint32_t eproc) {
#if defined(TARGET_I386)
                uint32_t pid;
                if(-1 == panda_virtual_memory_rw(cpu, eproc+eproc_pid_off, (uint8_t *)&pid, 4, false)) return 0;
                return pid;
#endif
                return 0;
            }

            PTR get_ppid(CPUState *cpu, PTR eproc) {
#if defined(TARGET_I386)
                PTR ppid;
                if(-1 == panda_virtual_memory_rw(cpu, eproc+eproc_ppid_off, (uint8_t *)&ppid, sizeof(PTR), false)) return 0;
                return ppid;
#endif
                return 0;
            }

            PTR get_dtb(CPUState *cpu, PTR eproc) {
#if defined(TARGET_I386)
                PTR dtb = 0;
                int dtbReq = panda_virtual_memory_rw(cpu, eproc+EPROC_DTB_OFF, (uint8_t *)&dtb, sizeof(PTR), false);
                if (dtbReq == -1) {
                    return 0;
                }
                return dtb;
#endif
                return 0;
            }
            
            const char *get_mod_basename(CPUState *cpu, PTR mod) {
#if defined(TARGET_I386)
                return get_unicode_str(cpu, mod+LDR_BASENAME_OFF);
#endif
                return NULL;
            }

            const char *get_mod_filename(CPUState *cpu, PTR mod) {
#if defined(TARGET_I386)
                return get_unicode_str(cpu, mod+LDR_FILENAME_OFF);
#endif
                return NULL;
            }

            PTR get_mod_base(CPUState *cpu, PTR mod) {
#if defined(TARGET_I386)
                PTR base = 0;
                int ret = panda_virtual_memory_rw(cpu, mod+LDR_BASE_OFF, (uint8_t *)&base, sizeof(PTR), false);
                if (ret == -1) {
                    return 0;
                }
                return base;
#endif
                return 0;
            }

            PTR get_mod_size(CPUState *cpu, PTR mod) {
#if defined(TARGET_I386)
                uint32_t size;
                int ret = panda_virtual_memory_rw(cpu, mod+LDR_SIZE_OFF, (uint8_t *)&size, sizeof(uint32_t), false);
                if (ret == -1) {
                    return 0;
                }
                return size;
#endif
                return 0;
            }
            
            PTR get_next_mod(CPUState *cpu, PTR mod) {
#if defined(TARGET_I386)
                
                PTR next;
                if (-1 == panda_virtual_memory_rw(cpu, mod+LDR_LOAD_LINKS_OFF, (uint8_t *)&next, sizeof(PTR), false))
                    return 0;
                next -= LDR_LOAD_LINKS_OFF;
                return next;
#endif
                return 0;
            }
            
            void add_mod(CPUState *cpu, OsiModules *ms, PTR mod, bool ignore_basename) {
#if defined(TARGET_I386)                
                
//#ifdef _DEBUG
//                fprintf(gDebugFile, ">> add_mod(%p, 0x%08x, %d)\n", ms, mod, ignore_basename);
//                fflush(gDebugFile);
//#endif
                static uint32_t capacity = 8;
                if ((ms->module == NULL ) || (ms->num == capacity)) {
                    if (ms->module != NULL) {
                        capacity *= 2;  // forget this fucker, since ms->module is always NULL at the beginning, 
                                    // this just multiplied without bounds!
                    }
//#ifdef _DEBUG
//                    fprintf(gDebugFile, " - capacity: %ld\n", (int64_t)capacity);
//                    fflush(gDebugFile);
//#endif
                    ms->module = (OsiModule *)realloc(ms->module, sizeof(OsiModule) * capacity);
                    assert(ms->module); // somehow, this is null. realloc returns null if no more memory available
                }
//#ifdef _DEBUG
//                if (ms) {
//                    // why ms->module is null?
//                    fprintf(gDebugFile, " - ms->module: %p\n", ms->module);
//                    fflush(gDebugFile);
//                }
//#endif
                OsiModule *p = &ms->module [ms->num++];
                fill_osimod(cpu, p, mod, ignore_basename);
//#ifdef _DEBUG
//                fprintf(gDebugFile, "<< add_mod()\n");
//                fflush(gDebugFile);
//#endif
                
#endif
            }


            void get_procname(CPUState *cpu, uint32_t eproc, char **name) {
#if defined(TARGET_I386)
                assert(name);
                *name = (char *) malloc(17);
                assert(*name); // fine!
                int nameReq = panda_virtual_memory_rw(cpu, eproc+eproc_name_off, (uint8_t *)*name, 16, false);
                if (nameReq == -1) {
                    strncpy(*name, "(paged)", 7);
                }
                (*name)[16] = '\0';
#endif
            }
            
            void fill_osiproc(CPUState *cpu, OsiProc *p, PTR eproc) {
#if defined(TARGET_I386)
                p->offset = eproc;
                get_procname(cpu, eproc, &p->name);
                p->asid = get_dtb(cpu, eproc);
                p->pages = NULL;
                p->pid = get_pid(cpu, eproc);
                p->ppid = get_ppid(cpu, eproc);
#endif
            }
            
            void fill_osimod(CPUState *cpu, OsiModule *m, PTR mod, bool ignore_basename) {
#if defined(TARGET_I386)
//#ifdef _DEBUG
//                // problem, m is NULL!
//                fprintf(gDebugFile, ">> fill_osimod(%p, 0x%08x, %d)\n", m, mod, ignore_basename);
//                fflush(gDebugFile);
//#endif
                m->offset = mod;
                m->file = (char *)get_mod_filename(cpu, mod);
                m->base = get_mod_base(cpu, mod);
                m->size = get_mod_size(cpu, mod);
                m->name = ignore_basename ? g_strdup("-") : (char *)get_mod_basename(cpu, mod);
//#ifdef _DEBUG
//                fprintf(gDebugFile, " - m->name: %s\n", m->name);
//                fflush(gDebugFile);
//#endif
                assert(m->name);
//#ifdef _DEBUG
//                fprintf(gDebugFile, "<< fill_osimod()\n");
//                fflush(gDebugFile);
//#endif
                
#endif
            }

            void internal_get_current_process(CPUState *cpu, OsiProc **out_p) {
#if defined(TARGET_I386)
                PTR eproc = get_current_proc(cpu);
                if(eproc) {
                    OsiProc *p = (OsiProc *) malloc(sizeof(OsiProc));
                    fill_osiproc(cpu, p, eproc);
                    *out_p = p;
                } else {
                    *out_p = NULL;
                }
#endif
            }
            
            OsiProc * get_current_process(CPUState *cpu) {
                OsiProc *p = NULL;
                internal_get_current_process(cpu, &p);
                return p;
            }

            uint32_t get_current_proc(CPUState *cpu) {
#if defined(TARGET_I386)
                PTR thread, proc;
                PTR kpcr = get_kpcr(cpu);

                // Read KPCR->CurrentThread->Process
                if (-1 == panda_virtual_memory_rw(cpu, kpcr+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, sizeof(PTR), false)) return 0;
                if (-1 == panda_virtual_memory_rw(cpu, thread+get_kthread_kproc_off(), (uint8_t *)&proc, sizeof(PTR), false)) return 0;

                // Sometimes, proc == 0 here.  Is there a better way to do this?

                return is_valid_process(cpu, proc) ? proc : 0;
#endif
                return 0;
            }
            
            void internal_get_libraries(CPUState *cpu, OsiProc *p, OsiModules **out_ms) {
#if defined(TARGET_I386)
                
                // Find the process we're interested in
                PTR eproc = get_current_proc(cpu);
                if(!eproc) {
//#ifdef _DEBUG
//                    fprintf(gDebugFile, " - get_current_proc failed\n");
//                    fflush(gDebugFile);
//#endif
                    *out_ms = NULL; 
                    return;
                }

                bool found = false;
                PTR first_proc = eproc;
                do {
                    if (eproc == p->offset) {
                        found = true;
                        break;
                    }
                    eproc = get_next_proc(cpu, eproc);
                    if (!eproc) break;
                } while (eproc != first_proc);

                if (!found) {
//#ifdef _DEBUG
//                    fprintf(gDebugFile, " - process not found\n");
//                    fflush(gDebugFile);
//#endif
                    *out_ms = NULL; 
                    return;
                }

                OsiModules *ms = (OsiModules *)malloc(sizeof(OsiModules));
                ms->num = 0;
                ms->module = NULL;
                PTR peb = 0, ldr = 0;
                // PEB->Ldr->InMemoryOrderModuleList
                if (-1 == panda_virtual_memory_rw(cpu, eproc+EPROC_PEB_OFF, (uint8_t *)&peb, sizeof(PTR), false) ||
                    -1 == panda_virtual_memory_rw(cpu, peb+PEB_LDR_OFF, (uint8_t *)&ldr, sizeof(PTR), false)) {
//#ifdef _DEBUG
//                    // if reaches here, ms cannot be freed!
//                    fprintf(gDebugFile, " - unable to read eproc peb or peb ldr offset\n");
//                    fflush(gDebugFile);
//#endif
                    *out_ms = NULL; return;
                }
                
//#ifdef _DEBUG
//                fprintf(gDebugFile, " - searching for modules, peb=0x%08x, ldr=0x%08x\n", peb, ldr);
//                fflush(gDebugFile);
//#endif

                // Fake "first mod": the address of where the list head would
                // be if it were a LDR_DATA_TABLE_ENTRY
                PTR first_mod = ldr+PEB_LDR_LOAD_LINKS_OFF-LDR_LOAD_LINKS_OFF;
                PTR current_mod = get_next_mod(cpu, first_mod);
                // We want while loop here -- we are starting at the head,
                // which is not a valid module
                
//#ifdef _DEBUG
//                fprintf(gDebugFile, " - first_mod: 0x%08x\n", first_mod);
//                fflush(gDebugFile);
//#endif
                
                while (current_mod != first_mod) {
//#ifdef _DEBUG
//                    fprintf(gDebugFile, " - current module: 0x%08x\n", current_mod);
//                    fflush(gDebugFile);
//#endif
                    add_mod(cpu, ms, current_mod, false);
                    current_mod = get_next_mod(cpu, current_mod);
                    if (!current_mod) break;
                }

                *out_ms = ms;
                return;
                
#endif
            }
            
            OsiModules * get_libraries(CPUState * cpu, OsiProc *proc) {
//#ifdef _DEBUG
//                fprintf(gDebugFile, ">> get_libraries\n");
//#endif
                OsiModules * mod;
                internal_get_libraries(cpu, proc, &mod);
                
//#ifdef _DEBUG
//                fprintf(gDebugFile, "<< get_libraries(): returns %p\n", mod);
//#endif
                
                return mod;
            }
            
            char *make_pagedstr(void) {
                char *m = g_strdup("(paged)");
                assert(m);
                return m;
            }
            
            // Gets a unicode string. Does its own mem allocation.
            // Output is a null-terminated UTF8 string
            char *get_unicode_str(CPUState *cpu, PTR ustr) {
#if defined(TARGET_I386)
                uint16_t size = 0;
                PTR str_ptr = 0;
                if (-1 == panda_virtual_memory_rw(cpu, ustr, (uint8_t *)&size, 2, false)) {
                    return make_pagedstr();
                }

                // Clamp size
                if (size > 1024) size = 1024;
                if (-1 == panda_virtual_memory_rw(cpu, ustr+4, (uint8_t *)&str_ptr, 4, false)) {
                    return make_pagedstr();
                }

                gchar *in_str = (gchar *)g_malloc0(size);
                if (-1 == panda_virtual_memory_rw(cpu, str_ptr, (uint8_t *)in_str, size, false)) {
                    g_free(in_str);
                    return make_pagedstr();
                }

                gsize bytes_written = 0;
                gchar *out_str = g_convert(in_str, size,
                        "UTF-8", "UTF-16LE", NULL, &bytes_written, NULL);

                // An abundance of caution: we copy it over to something allocated
                // with our own malloc. In the future we need to provide a way for
                // someone else to free the memory allocated in here...
                char *ret = (char *)malloc(bytes_written+1);
                memcpy(ret, out_str, bytes_written+1);
                g_free(in_str);
                g_free(out_str);
                return ret;
#endif
                return NULL;
            }

        }
        
        bool init_system() {
            return x86sp1::init_system();
        }
        
        OsiProc * get_current_process(CPUState *cpu) {
            return x86sp1::get_current_process(cpu);
        }
        
        OsiModules * get_libraries(CPUState * cpu, OsiProc *proc) {
            return x86sp1::get_libraries(cpu, proc);
        }
        
        void free_osiprocs(OsiProcs *ps) {
            if(!ps) return;
            if(ps->proc) {
                for(uint32_t i = 0; i < ps->num; i++) {
                    free(ps->proc[i].name);
                }
                free(ps->proc);
            }
            free(ps);
        }
        
        void free_osiproc(OsiProc *p) {
            if (!p) return;
            free(p->name);
            free(p);
        }

        void free_osimodules(OsiModules *ms) {
            if(!ms) return;
            if(ms->module) {
                for(uint32_t i = 0; i < ms->num; i++) {
                    free(ms->module[i].file);
                    free(ms->module[i].name);
                }
                free(ms->module);
            }
            free(ms);
        }
    }
}
