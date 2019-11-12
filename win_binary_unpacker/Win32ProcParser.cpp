/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "panda/plugin.h"
#include "panda/common.h"

#include "Win32ProcParser.h"
#include "logger.h"
#include "pe_module.h"

#include "windefs.h"
#include "winxpstruct.h"
#include "winhelper.h"

#include <cstdio>
#include <cstring>

#include <vector>
using std::vector;

namespace unpacker {
    namespace winpe32 {

        Win32ProcParser::Win32ProcParser()
        : m_is_parsed(false) {

        }

        Win32ProcParser::~Win32ProcParser() {

        }

        /**
         * function to read memory using virtual addressing mode
         * @param ProcessInfo& proc, reference to ProcessInfo class
         * @param types::addr_t src, starting address to be read
         * @param types::byte_t* out, out buffer
         * @param int size, size of the memory to read
         * @param void * opaque, any object to be sent.
         *     In this class, this is pointer to CPUState structure
         * @return 0 if error, otherwise, the number of bytes read
         */
        int Win32ProcParser::read_mem(
                ProcessInfo& proc,
                types::addr_t src,
                types::byte_t* out,
                int size,
                void * opaque) {

            if (opaque == NULL) {
                return 0;
            }

            CPUState * env = reinterpret_cast<CPUState*>(opaque);

            if (-1 != panda_virtual_memory_read(env, (uint32_t)src, out, size)) {
                return size;
            }

            //MYWARN("Unable to read memory from PANDA at 0x%016lx with size 0x%x (%d)",
            //            src, size, size);

            // mem read error, try reading from clone
            if (proc.read_cloned_memory(src, size, out)) {
                return size;
            }

            //MYERROR("Unable to read memory from cloned memory at 0x%016lx with size 0x%x (%d)",
            //    src, size, size);

            return 0;

        }

        bool Win32ProcParser::is_in_kernel(void * opaque) {

            if (opaque == NULL) {
                return false;
            }

            CPUState * env = reinterpret_cast<CPUState*>(opaque);

            return panda_in_kernel(env);

        }

//        types::addr_t Win32ProcParser::get_opt_hdr_rva(types::addr_t base_addr,
//                void* opaque) {
//
//            winxpsp3x86::IMAGE_DOS_HEADER dos_header;
//            if (!this->read_mem(proc,base_addr, (types::byte_t*)(&dos_header),
//                    winxpsp3x86::SIZEOF_IMAGE_DOS_HEADER, opaque)) {
//
//                MYERROR("Unable to read memory at 0x%016lx", base_addr);
//                return 0;
//            }
//
//            winxpsp3x86::LONG rva_pe_hdr = dos_header.e_lfanew;
//
//            winxpsp3x86::ULONG rva_opt_hdr = rva_pe_hdr +
//                    winxpsp3x86::SIZEOF_PE_SIGNATURE +
//                    winxpsp3x86::SIZEOF_IMAGE_FILE_HEADER;
//
//            return rva_opt_hdr;
//
//        }

        void Win32ProcParser::parse(ProcessInfo& proc,
                types::addr_t base_addr, void* opaque) {

            /*
            if (base_addr >= (types::addr_t)0x70000000) {
                return;
            }
            */

            if (!this->m_is_parsed) {

                if (this->is_in_kernel(opaque)) {
                    return;
                }

                // change of plan, read all buffers first, then find them

                //MYINFO("Try finding target process base address in 0x%016x", base_addr);

                // read PE file here
                winxpsp3x86::IMAGE_DOS_HEADER dos_header;
                if (!this->read_mem(proc,base_addr, (types::byte_t*)(&dos_header),
                        winxpsp3x86::SIZEOF_IMAGE_DOS_HEADER, opaque)) {

                    //MYERROR("Unable to read memory at 0x%016lx", base_addr);
                    return;
                }

                winxpsp3x86::LONG rva_pe_hdr = dos_header.e_lfanew;

                //MYINFO("dos_header.MAGIC = %04x", dos_header.e_magic);
                //MYINFO("dos_header.rva_pe_hdr = 0x%08x", rva_pe_hdr);

                if (dos_header.e_magic != winxpsp3x86::IMAGE_DOS_SIGNATURE) {
                    // NOT PE!
                    return;
                }

                winxpsp3x86::DWORD pe_sig = 0;
                if (!this->read_mem(proc,
                    base_addr + rva_pe_hdr,
                    (types::byte_t*)(&pe_sig),
                    winxpsp3x86::SIZEOF_PE_SIGNATURE,
                    opaque)) {

                    //MYERROR("Unable to read PE header signature at 0x%016lx", base_addr + rva_pe_hdr);
                    return;
                }

                //MYINFO("PE SIGNATURE = 0x%08x", pe_sig);

                // PE signature 4 bytes
                if (pe_sig != winxpsp3x86::IMAGE_NT_SIGNATURE) {
                    // NOT PE!
                    return;
                }

                MYINFO("Try reading PE at 0x%016lx", base_addr);

                proc.get_module().set_base_addr(base_addr);

                winxpsp3x86::ULONG rva_opt_hdr = rva_pe_hdr +
                        winxpsp3x86::SIZEOF_PE_SIGNATURE +
                        winxpsp3x86::SIZEOF_IMAGE_FILE_HEADER;

                MYINFO("rva_opt_hdr = 0x%08x", rva_opt_hdr);

                // read PE image size
                winxpsp3x86::IMAGE_OPTIONAL_HEADER opt_header;
                if (!this->read_mem(proc,
                        base_addr + rva_opt_hdr,
                        (types::byte_t*)(&opt_header),
                        winxpsp3x86::SIZEOF_IMAGE_OPTIONAL_HEADER,
                        opaque)) {

                    MYERROR("Unable to read Optional Header at 0x%016lx",
                            base_addr + rva_opt_hdr);
                    return;
                }

                MYINFO("IMAGE_OPTIONAL_HEADER.SizeOfImage = 0x%08x", opt_header.SizeOfImage);

                // possible that the memory is paged?
                // if memory is paged, it will be error!
                // If this is the case, should only access the current page?
                vector<types::byte_t> exe_buf(opt_header.SizeOfImage);
                if (!this->read_mem(proc,base_addr, (types::byte_t*)&exe_buf[0], opt_header.SizeOfImage, opaque)) {
                    MYERROR("Unable to read PE memory image at 0x%016lx",
                            base_addr);
                    return;
                }

                proc.get_module().set_image_size(opt_header.SizeOfImage);

                // read FILE HEADER
                winxpsp3x86::IMAGE_FILE_HEADER file_header;
                winxpsp3x86::LONG rva_file_hdr = rva_pe_hdr + winxpsp3x86::SIZEOF_PE_SIGNATURE;

                if (!this->read_mem(proc,
                        base_addr + rva_file_hdr,
                        (types::byte_t*)(&file_header),
                        winxpsp3x86::SIZEOF_IMAGE_FILE_HEADER,
                        opaque)) {

                    MYERROR("Unable to read File Header at 0x%016lx",
                            base_addr + rva_file_hdr);
                    return;

                }

                MYINFO("IMAGE_FILE_HEADER.TimeDateStamp = 0x%08x", file_header.TimeDateStamp);

                proc.get_module().set_timestamp(file_header.TimeDateStamp);

                // image_name should be full path + binary name, not just
                // the process name
                // TODO: image name --> find modules, find first, convert UNICODE_STRING to ascii

                // sections
                int num_of_sections = file_header.NumberOfSections;
                MYINFO("IMAGE_FILE_HEADER.NumberOfSections = 0x%08x", num_of_sections);

                winxpsp3x86::LONG rva_sec_hdr = rva_opt_hdr +
                        winxpsp3x86::SIZEOF_IMAGE_OPTIONAL_HEADER;

                vector<winxpsp3x86::IMAGE_SECTION_HEADER> v_section_header(
                        num_of_sections + 1);

                if (!this->read_mem(proc,
                        base_addr + rva_sec_hdr,
                        (types::byte_t*)(&v_section_header[0]),
                        num_of_sections * winxpsp3x86::SIZEOF_IMAGE_SECTION_HEADER,
                        opaque)) {

                    MYERROR("Unable to read Section Headers at 0x%016lx",
                            base_addr + rva_sec_hdr);
                    return;

                }

                MYINFO("Reading sections at 0x%08x", (uint32_t)(base_addr + rva_sec_hdr));

                for (int i=0; i<num_of_sections; ++i) {
                    winxpsp3x86::IMAGE_SECTION_HEADER& sec_hdr = v_section_header[i];
                    unpacker::module::PESection pe_sec;

                    pe_sec.name = (char*)sec_hdr.Name;
                    pe_sec.characteristics = sec_hdr.Characteristics;
                    pe_sec.disk_size = sec_hdr.SizeOfRawData;
                    pe_sec.rva_disk_addr = sec_hdr.PointerToRawData;
                    pe_sec.rva_virtual_addr = sec_hdr.VirtualAddress;
                    pe_sec.virtual_size = sec_hdr.Misc.VirtualSize;

                    MYINFO("\tName = %s", pe_sec.name.c_str());
                    MYINFO("\tCharacteristics = 0x%08x", pe_sec.characteristics);
                    MYINFO("\tSizeOfRawData = 0x%08x", pe_sec.disk_size);
                    MYINFO("\tPointerToRawData = 0x%08x", pe_sec.rva_disk_addr);
                    MYINFO("\tVirtualAddress = 0x%08x", pe_sec.rva_virtual_addr);
                    MYINFO("\tMisc.VirtualSize = 0x%08x", pe_sec.virtual_size);
                    MYINFO("%s", "=====================================");

                    proc.get_module().get_sections().push_back(pe_sec);
                }

                // imports
                winxpsp3x86::IMAGE_DATA_DIRECTORY& import_data_dir =
                        opt_header.DataDirectory[winxpsp3x86::IMAGE_DATA_DIRECTORY_ENTRY::IMPORT_TABLE];
                winxpsp3x86::DWORD rva_import_dir = import_data_dir.VirtualAddress;
                winxpsp3x86::DWORD import_virtual_size = import_data_dir.Size;
                int num_imp_dir = import_virtual_size / winxpsp3x86::SIZEOF_IMAGE_IMPORT_DIRECTORY;

                MYINFO("Reading Imports data from PE file at VA 0x%08x", (uint32_t)(base_addr + rva_import_dir) );
                MYINFO("\tRVA import directory = 0x%08x", rva_import_dir);
                MYINFO("\tImport Directory Virtual Size = 0x%08x", import_virtual_size);
                MYINFO("\tNumber of Import Directories (exclude all zeros) = %d", num_imp_dir - 1);

                vector<winxpsp3x86::IMAGE_IMPORT_DIRECTORY> v_image_import_dir(num_imp_dir);
                if (!this->read_mem(proc,
                        base_addr + rva_import_dir,
                        (types::byte_t*)(&v_image_import_dir[0]),
                        import_virtual_size,
                        opaque)) {

                    MYERROR("Unable to read Import Directory Table at 0x%016lx",
                            base_addr + rva_import_dir);
                    return;

                }

                // last element is zeroed out.
                for (int i=0; i<num_imp_dir-1; ++i) {
                    winxpsp3x86::IMAGE_IMPORT_DIRECTORY& imgdir = v_image_import_dir[i];
                    unpacker::module::PEImport imp;

                    char * dll_name = (char*)&exe_buf[imgdir.ImportedDLLName];
                    imp.dll_name = dll_name;

                    char * func_name;
                    char ord_func[32];
                    memset(ord_func, 0, sizeof(ord_func));

                    for (int i=0 ; ; ++i) {
                        winxpsp3x86::ULONG func_addr = *(reinterpret_cast<winxpsp3x86::ULONG*>(
                                &exe_buf[imgdir.ImportNameTableRva + i * sizeof(winxpsp3x86::ULONG)]));

                        if (func_addr == 0) {
                            break;
                        }

                        if (func_addr & (winxpsp3x86::ULONG)0x80000000) {
                            // ordinal
                            snprintf(ord_func, 31, "(ORD)0x%08x", func_addr);
                            func_name = ord_func;

                        } else {
                            // rva
                            func_name = (char*)&exe_buf[func_addr];

                        }

                        imp.v_import_func_name.push_back(string(func_name));
                    }

                    proc.get_module().get_imports().push_back(imp);
                }


                int import_size = (int) proc.get_module().get_imports().size();
                MYINFO("Dump Import Information, length = %d", import_size);

                for (int i = 0; i<import_size; ++i) {
                    unpacker::module::PEImport& imp = proc.get_module().get_imports()[i];

                    MYINFO("\tImported DLL Name = %s", imp.dll_name.c_str());

                    int nfunc = (int) imp.v_import_func_name.size();
                    for (int j = 0; j<nfunc; ++j) {
                        MYINFO("\t\t%s", imp.v_import_func_name[j].c_str());
                    }
                }

                // exports, since handle exe files, this is expected to be empty


                this->m_is_parsed = true;
            }

        }

    }
}
