/*
 * win32struct.h
 *
 *  Created on: Mar 30, 2018
 *      Author: darryl
 */

#ifndef WIN32PEHEADER_H_
#define WIN32PEHEADER_H_

#include <stdint.h>

namespace panda {
    namespace win {

        typedef uint16_t WORD;
        typedef uint32_t DWORD;
        typedef int32_t LONG;
        typedef uint32_t ULONG;
        typedef uint64_t QWORD;
        typedef uint64_t ULONGLONG;
        typedef uint8_t BYTE;

        // image data directory stuff

        enum IMAGE_DATA_DIRECTORY_ENTRY {
            IMAGE_DATA_DIRECTORY_ENTRY_EXPORT_TABLE = 0,
            IMAGE_DATA_DIRECTORY_ENTRY_IMPORT_TABLE = 1,
            IMAGE_DATA_DIRECTORY_ENTRY_RESOURCE = 2,
            IMAGE_DATA_DIRECTORY_ENTRY_EXCEPTION = 3,
            IMAGE_DATA_DIRECTORY_ENTRY_CERTIFICATE = 4,
            IMAGE_DATA_DIRECTORY_ENTRY_BASE_RELOCATION = 5,
            IMAGE_DATA_DIRECTORY_ENTRY_DEBUG = 6,
            IMAGE_DATA_DIRECTORY_ENTRY_ARCH = 7,
            IMAGE_DATA_DIRECTORY_ENTRY_GLOBAL_POINTER = 8,
            IMAGE_DATA_DIRECTORY_ENTRY_TLS = 9,
            IMAGE_DATA_DIRECTORY_ENTRY_LOAD_CONFIG = 10,
            IMAGE_DATA_DIRECTORY_ENTRY_BOUND_IMPORT = 11,
            IMAGE_DATA_DIRECTORY_ENTRY_IMPORT_ADDRESS_TABLE = 12,
            IMAGE_DATA_DIRECTORY_ENTRY_DELAY_IMPORT = 13,
            IMAGE_DATA_DIRECTORY_ENTRY_CLI_HEADER = 14,
            IMAGE_DATA_DIRECTORY_ENTRY_RESERVED = 15,
            IMAGE_DATA_DIRECTORY_ENTRY_LENGTH = 16
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
            WORD Machine;
            WORD NumberOfSections;
            DWORD TimeDateStamp;
            DWORD PointerToSymbolTable;
            DWORD NumberOfSymbols;
            WORD SizeOfOptionalHeader;
            WORD Characteristics;
        } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

        typedef struct _IMAGE_DATA_DIRECTORY {
            DWORD VirtualAddress;
            DWORD Size;
        } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

        typedef struct _IMAGE_OPTIONAL_HEADER {
            WORD Magic;
            BYTE MajorLinkerVersion;
            BYTE MinorLinkerVersion;
            DWORD SizeOfCode;
            DWORD SizeOfInitializedData;
            DWORD SizeOfUninitializedData;
            DWORD AddressOfEntryPoint;
            DWORD BaseOfCode;
            DWORD BaseOfData;
            DWORD ImageBase;
            DWORD SectionAlignment;
            DWORD FileAlignment;
            WORD MajorOperatingSystemVersion;
            WORD MinorOperatingSystemVersion;
            WORD MajorImageVersion;
            WORD MinorImageVersion;
            WORD MajorSubsystemVersion;
            WORD MinorSubsystemVersion;
            DWORD Win32VersionValue;
            DWORD SizeOfImage;
            DWORD SizeOfHeaders;
            DWORD CheckSum;
            WORD Subsystem;
            WORD DllCharacteristics;
            DWORD SizeOfStackReserve;
            DWORD SizeOfStackCommit;
            DWORD SizeOfHeapReserve;
            DWORD SizeOfHeapCommit;
            DWORD LoaderFlags;
            DWORD NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_DATA_DIRECTORY_ENTRY_LENGTH];
        } IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

        typedef struct _IMAGE_NT_HEADERS {
            DWORD Signature;
            IMAGE_FILE_HEADER FileHeader;
            IMAGE_OPTIONAL_HEADER OptionalHeader;
        } IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

        typedef struct _IMAGE_EXPORT_DIRECTORY {
            DWORD Characteristics;
            DWORD TimeDateStamp;
            WORD MajorVersion;
            WORD MinorVersion;
            DWORD Name;
            DWORD Base;
            
            // number of functions exported by this dll (ordinal + name)
            DWORD NumberOfFunctions;
            
            // number of functions exported by this dll (name only). This number
            // will be equal or less than number of functions
            DWORD NumberOfNames;
            DWORD AddressOfFunctions; // RVA from base of image
            DWORD AddressOfNames; // RVA from base of image
            DWORD AddressOfNameOrdinals; // RVA from base of image
        } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
            BYTE Name[IMAGE_SIZEOF_SHORT_NAME];

            union {
                DWORD PhysicalAddress;
                DWORD VirtualSize;
            } Misc;
            DWORD VirtualAddress;
            DWORD SizeOfRawData;
            DWORD PointerToRawData;
            DWORD PointerToRelocations;
            DWORD PointerToLinenumbers;
            WORD NumberOfRelocations;
            WORD NumberOfLinenumbers;
            DWORD Characteristics;
        } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define SIZEOF_PE_SIGNATURE sizeof(panda::win::DWORD)
#define SIZEOF_IMAGE_FILE_HEADER sizeof(panda::win::IMAGE_FILE_HEADER)
#define SIZEOF_IMAGE_OPTIONAL_HEADER sizeof(panda::win::IMAGE_OPTIONAL_HEADER)
#define SIZEOF_IMAGE_EXPORT_DIRECTORY sizeof(panda::win::IMAGE_EXPORT_DIRECTORY)

    }
}

#endif /* WIN32STRUCT_H_ */
