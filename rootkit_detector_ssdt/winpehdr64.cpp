/*
 * TODO: complete the 64-bit windows PE
 * Seems like that we must inspect the pe header with PEView manually
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "winpehdr64.h"

// constants

// 'ZM' due to little endian
#define WIN_PE_MZ_TAG 			0x5a4d

// 4 bytes, offset of the address of PE exe header from MZ header
#define WIN_PE_ADDR_OFF 		0x3c

// end

namespace winpe {

    typedef uint16_t WORD;
    typedef uint32_t DWORD;
    typedef int32_t LONG;
    typedef uint32_t ULONG;
    typedef uint64_t QWORD;
    typedef uint64_t ULONGLONG;
    typedef uint8_t BYTE;
    
    // image data directory stuff
    enum IMAGE_DATA_DIRECTORY_ENTRY {
        EXPORT_TABLE = 0,
        IMPORT_TABLE = 1,
        RESOURCE = 2,
        EXCEPTION = 3,
        CERTIFICATE = 4,
        BASE_RELOCATION = 5,
        DEBUG = 6,
        ARCH = 7,
        GLOBAL_POINTER = 8,
        TLS = 9,
        LOAD_CONFIG = 10,
        BOUND_IMPORT = 11,
        IMPORT_ADDRESS_TABLE = 12,
        DELAY_IMPORT = 13,
        CLI_HEADER = 14,
        RESERVED = 15,
        LENGTH = 16
    };
    
    typedef struct _IMAGE_DOS_HEADER {
        WORD e_magic;
        WORD e_cblp;
        WORD e_cp;
        WORD e_crlc;
        WORD e_cparhdr;
        WORD e_minalloc;
        WORD e_maxalloc;
        WORD e_ss;
        WORD e_sp;
        WORD e_csum;
        WORD e_ip;
        WORD e_cs;
        WORD e_lfarlc;
        WORD e_ovno;
        WORD e_res[4];
        WORD e_oemid;
        WORD e_oeminfo;
        WORD e_res2[10];
        LONG e_lfanew;
   } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

    typedef struct _IMAGE_FILE_HEADER {
        WORD  Machine;
        WORD  NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD  SizeOfOptionalHeader;
        WORD  Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

    typedef struct _IMAGE_OPTIONAL_HEADER64 {
        WORD        Magic;
        BYTE        MajorLinkerVersion;
        BYTE        MinorLinkerVersion;
        DWORD       SizeOfCode;
        DWORD       SizeOfInitializedData;
        DWORD       SizeOfUninitializedData;
        DWORD       AddressOfEntryPoint;
        DWORD       BaseOfCode;
        ULONGLONG   ImageBase;
        DWORD       SectionAlignment;
        DWORD       FileAlignment;
        WORD        MajorOperatingSystemVersion;
        WORD        MinorOperatingSystemVersion;
        WORD        MajorImageVersion;
        WORD        MinorImageVersion;
        WORD        MajorSubsystemVersion;
        WORD        MinorSubsystemVersion;
        DWORD       Win32VersionValue;
        DWORD       SizeOfImage;
        DWORD       SizeOfHeaders;
        DWORD       CheckSum;
        WORD        Subsystem;
        WORD        DllCharacteristics;
        ULONGLONG   SizeOfStackReserve;
        ULONGLONG   SizeOfStackCommit;
        ULONGLONG   SizeOfHeapReserve;
        ULONGLONG   SizeOfHeapCommit;
        DWORD       LoaderFlags;
        DWORD       NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_DATA_DIRECTORY_ENTRY::LENGTH];
    } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64, IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

    typedef struct _IMAGE_NT_HEADERS {
        DWORD                 Signature;
        IMAGE_FILE_HEADER     FileHeader;
        IMAGE_OPTIONAL_HEADER OptionalHeader;
    } IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
    
    typedef struct _IMAGE_EXPORT_DIRECTORY {
        DWORD Characteristics;
        DWORD TimeDateStamp;
        WORD MajorVersion;
        WORD MinorVersion;
        DWORD Name;
        DWORD Base;
        DWORD NumberOfFunctions;
        DWORD NumberOfNames;
        DWORD AddressOfFunctions;     // RVA from base of image
        DWORD AddressOfNames;     // RVA from base of image
        DWORD AddressOfNameOrdinals;  // RVA from base of image
    } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
    
    #define IMAGE_SIZEOF_SHORT_NAME 8
    typedef struct _IMAGE_SECTION_HEADER {
        BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
                DWORD PhysicalAddress;
                DWORD VirtualSize;
        } Misc;
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD PointerToRelocations;
        DWORD PointerToLinenumbers;
        WORD  NumberOfRelocations;
        WORD  NumberOfLinenumbers;
        DWORD Characteristics;
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

    #define SIZEOF_PE_SIGNATURE sizeof(DWORD)
    #define SIZEOF_IMAGE_FILE_HEADER sizeof(IMAGE_FILE_HEADER)
    #define SIZEOF_IMAGE_OPTIONAL_HEADER sizeof(IMAGE_OPTIONAL_HEADER)
    #define SIZEOF_IMAGE_EXPORT_DIRECTORY sizeof(IMAGE_EXPORT_DIRECTORY)
    
    
    
    
    // why do i do this?
    class ARRPTRHANDLE {
    public:
        ARRPTRHANDLE(uint8_t *ptr) 
        : m_ptr(ptr)
        {
            
        }
        
        ~ARRPTRHANDLE() {
            delete [] m_ptr;
        }
        
        uint8_t *get() {
            return m_ptr;
        }
        
    private:
        ARRPTRHANDLE(ARRPTRHANDLE const &);
        void operator=(ARRPTRHANDLE const &);
        
        uint8_t *m_ptr;
    };
    
    WinPE::WinPE(peaddr_t pe_base, FILE* dump_file)
    : m_pe_base(pe_base), m_dump(dump_file)
    {
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "WinPE::WinPE(0x%08x)\n", m_pe_base);
#endif
    }
    
    WinPE::WinPE(peaddr_t pe_base) 
    : m_pe_base(pe_base), m_dump(NULL)
    {
    }
    
    WinPE::~WinPE() {
        // does nothing
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "WinPE::~WinPE()\n");
#endif
    }
    
    peaddr_t WinPE::_get_opthdr_off() {
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, ">> WinPE::_get_opthdr_off()\n");
#endif
        
        DWORD pe_off;
        if (0 == this->read_mem(
                this->m_pe_base + WIN_PE_ADDR_OFF,
                (uint8_t*)&pe_off, sizeof(DWORD))) {
            return 0;
        }
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "pe_off=0x%08x\n", pe_off);
#endif
        
        DWORD imgopthdr_off = pe_off + SIZEOF_PE_SIGNATURE + SIZEOF_IMAGE_FILE_HEADER;
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "<< WinPE::_get_opthdr_off(): 0x%08x\n", imgopthdr_off);
#endif
        
        return imgopthdr_off;
    }
    
    bool WinPE::_read_image_opt_hdr(peaddr_t off, uint8_t* out, int size) {
        if (size >= SIZEOF_IMAGE_OPTIONAL_HEADER) {
            if (0 == this->read_mem(
                    off,
                    out, SIZEOF_IMAGE_OPTIONAL_HEADER)) {
                return false;
            }
            
            return true;
        }
        return false;
    }
    
    peaddr_t WinPE::get_low_addr() {
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, ">> WinPE::get_low_addr()\n");
#endif
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "<< WinPE::get_low_addr(): 0x%08x\n", this->m_pe_base);
#endif
        return this->m_pe_base;
    }
    
    peaddr_t WinPE::get_high_addr() {
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, ">> WinPE::get_high_addr()\n");
#endif        
        
        // m_pe_base + sizeofimage
        
        DWORD imgopthdr_off = this->_get_opthdr_off();
        
        IMAGE_OPTIONAL_HEADER opthdr;
        if (!this->_read_image_opt_hdr(this->m_pe_base + imgopthdr_off, 
                (uint8_t*)&opthdr, SIZEOF_IMAGE_OPTIONAL_HEADER)) {
            return 0;
        }
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "opthdr.SizeOfImage: 0x%08x\n", opthdr.SizeOfImage);
#endif
        
        peaddr_t high_addr = this->m_pe_base + opthdr.SizeOfImage - 1;
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "<< WinPE::get_high_addr(): 0x%08x\n", high_addr);
#endif
        
        return high_addr;
    }
    
    peaddr_t WinPE::get_export_func(const char* export_fn_name) {
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, ">> WinPE::get_export_func(%s)\n", export_fn_name);
#endif
        
        peaddr_t imgopthdr_off = this->_get_opthdr_off();
        
        IMAGE_OPTIONAL_HEADER opthdr;
        if (!this->_read_image_opt_hdr(this->m_pe_base + imgopthdr_off, 
                (uint8_t*)&opthdr, SIZEOF_IMAGE_OPTIONAL_HEADER)) {
            return 0;
        }
        
        IMAGE_DATA_DIRECTORY *export_data = &(opthdr.DataDirectory[
                IMAGE_DATA_DIRECTORY_ENTRY::EXPORT_TABLE]);
        
        peaddr_t imgexport_off = export_data->VirtualAddress;
        uint32_t imgexport_size = export_data->Size;
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "imgexport_RVA=0x%08x\n", imgexport_off);
        fprintf(this->m_dump, "imgexport_Size=0x%08x\n", imgexport_size);
#endif
        
        ARRPTRHANDLE imgexport_data_w(new uint8_t[imgexport_size+10]);
        
        if (0 == this->read_mem(
                this->m_pe_base + imgexport_off,
                imgexport_data_w.get(),
                imgexport_size)) {
            return 0;
        }
        
        uint8_t *imgexport_data = imgexport_data_w.get();
        
        IMAGE_EXPORT_DIRECTORY * imgexport_dir = (IMAGE_EXPORT_DIRECTORY *)imgexport_data;
        uint32_t imgexport_num_names = imgexport_dir->NumberOfNames;
        
        peaddr_t *fn_addr_tbl = (peaddr_t*)&(imgexport_data[
                imgexport_dir->AddressOfFunctions - export_data->VirtualAddress]);    
        
        peaddr_t *name_ptr_tbl = (peaddr_t*)&(imgexport_data[
                imgexport_dir->AddressOfNames - export_data->VirtualAddress]);
        
        WORD *name_ord_tbl = (WORD*)&(imgexport_data[
                imgexport_dir->AddressOfNameOrdinals - export_data->VirtualAddress]);
        
        uint32_t fn_ord = 0xFFFFFFFF;
        
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "Find Exports\n");
#endif
        
        for (uint32_t i=0; i<imgexport_num_names; ++i) {
            
            peaddr_t namepos = name_ptr_tbl[i];
            
            char * name = (char*)&(imgexport_data[namepos - export_data->VirtualAddress]);
            
#ifdef WINPE_DEBUG
            fprintf(this->m_dump, "name='%s'\n", name);
#endif
            
            if (strcmp(name, export_fn_name) == 0) {
                // found!
                fn_ord = name_ord_tbl[i];
                break;
            }
        }
        
        if (fn_ord == 0xFFFFFFFF) {
            return 0;
        }
        
        
        peaddr_t fn_addr = fn_addr_tbl[fn_ord];
        
#ifdef WINPE_DEBUG
        fprintf(this->m_dump, "fn_addr=0x%08x\n", fn_addr);
#endif
        
        // returns the real virtual address (not RVA!)
        return fn_addr + this->m_pe_base;
    }
};




