/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   winxpstruct.h
 * Author: darryl
 *
 * Created on August 16, 2017, 10:39 AM
 */

#ifndef WINXPSTRUCT_H
#define WINXPSTRUCT_H

namespace winxpsp3x86 {

    typedef uint16_t WORD;
    typedef uint16_t USHORT;
    typedef int16_t SHORT;
    typedef uint32_t DWORD;
    typedef int32_t LONG;
    typedef uint32_t ULONG;
    typedef uint64_t QWORD;
    typedef uint64_t ULONGLONG;
    typedef uint8_t BYTE;
    typedef uint8_t UCHAR;
    typedef int8_t CHAR;

    // PE FILE

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

        /* MZ header constant ('MZ') */
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

        /* RVA to PE Header at offset 0x3c (60) from MZ header */
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

    typedef struct _IMAGE_OPTIONAL_HEADER {
        WORD                 Magic;
        BYTE                 MajorLinkerVersion;
        BYTE                 MinorLinkerVersion;
        DWORD                SizeOfCode;
        DWORD                SizeOfInitializedData;
        DWORD                SizeOfUninitializedData;
        DWORD                AddressOfEntryPoint;
        DWORD                BaseOfCode;
        DWORD                BaseOfData;
        DWORD                ImageBase;
        DWORD                SectionAlignment;
        DWORD                FileAlignment;
        WORD                 MajorOperatingSystemVersion;
        WORD                 MinorOperatingSystemVersion;
        WORD                 MajorImageVersion;
        WORD                 MinorImageVersion;
        WORD                 MajorSubsystemVersion;
        WORD                 MinorSubsystemVersion;
        DWORD                Win32VersionValue;
        DWORD                SizeOfImage;
        DWORD                SizeOfHeaders;
        DWORD                CheckSum;
        WORD                 Subsystem;
        WORD                 DllCharacteristics;
        DWORD                SizeOfStackReserve;
        DWORD                SizeOfStackCommit;
        DWORD                SizeOfHeapReserve;
        DWORD                SizeOfHeapCommit;
        DWORD                LoaderFlags;
        DWORD                NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_DATA_DIRECTORY_ENTRY::LENGTH];
    } IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

    typedef struct _IMAGE_NT_HEADERS {
        DWORD                 Signature;
        IMAGE_FILE_HEADER     FileHeader;
        IMAGE_OPTIONAL_HEADER OptionalHeader;
    } IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

    typedef struct _IMAGE_IMPORT_DIRECTORY {

        // Address to array of DWORD, ended with 0, of RVA to function names or ordinals.
        // if it is RVA, the MSB is 0, if it ordinal, the MSB is 1.
        // example RVA will be: 000104CA while ordinal will be 80000146
        DWORD ImportNameTableRva;

        // always 0
        DWORD TimeDateStamp;

        // always 0
        DWORD ForwarderChain;

        // Address to the first character in zero-ended string of the dll name
        DWORD ImportedDLLName;

        // also known as FirstThunk in various places
        DWORD ImportAddressTableRva;
    } IMAGE_IMPORT_DIRECTORY, *PIMAGE_IMPORT_DIRECTORY;

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

    const int IMAGE_SIZEOF_SHORT_NAME  = 8;
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

    const int SIZEOF_PE_SIGNATURE = sizeof(DWORD);
    const int SIZEOF_IMAGE_DOS_HEADER = sizeof(IMAGE_DOS_HEADER);
    const int SIZEOF_IMAGE_FILE_HEADER = sizeof(IMAGE_FILE_HEADER);
    const int SIZEOF_IMAGE_OPTIONAL_HEADER = sizeof(IMAGE_OPTIONAL_HEADER);
    const int SIZEOF_IMAGE_EXPORT_DIRECTORY = sizeof(IMAGE_EXPORT_DIRECTORY);
    const int SIZEOF_IMAGE_SECTION_HEADER = sizeof(IMAGE_SECTION_HEADER);
    const int SIZEOF_IMAGE_IMPORT_DIRECTORY = sizeof(IMAGE_IMPORT_DIRECTORY);
    const int IMAGE_DOS_SIGNATURE = 0x5A4D;
    const int IMAGE_NT_SIGNATURE = 0x4550;

    // WIN INTERNALS

    typedef struct _LSA_UNICODE_STRING {

        // length, in bytes, of the string pointed to by Buffer
        // NOT INCLUDING the null terminator, if any.
        USHORT Length;
        USHORT MaximumLength;

        // pointer to wide character buffer (LPWSTR)
        // this is NOT ALWAYS ZERO TERMINATED!
        DWORD  Buffer;
    } LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

    // from https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx
    typedef struct _PEB {
        BYTE   Reserved1[2];
        BYTE   BeingDebugged;
        BYTE   Reserved2[1];
        DWORD  Reserved3[2];

        // A pointer to a PEB_LDR_DATA structure that contains information
        // about the loaded modules for the process.
        DWORD  Ldr;
        DWORD  ProcessParameters;
        BYTE   Reserved4[104];
        DWORD  Reserved5[52];
        DWORD  PostProcessInitRoutine;
        BYTE   Reserved6[128];
        DWORD  Reserved7[1];
        ULONG  SessionId;
    } PEB, *PPEB;

    typedef struct _LIST_ENTRY {
        DWORD Flink;
        DWORD Blink;
    } LIST_ENTRY, *PLIST_ENTRY;

    typedef struct _PEB_LDR_DATA {
        BYTE       Reserved1[8];
        DWORD      Reserved2[3];

        // The head of a doubly-linked list that contains the loaded modules for
        // the process. Each item in the list is a pointer to an LDR_DATA_TABLE_ENTRY structure.
        LIST_ENTRY InMemoryOrderModuleList;
    } PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        DWORD Reserved1[2];
        LIST_ENTRY InMemoryOrderLinks;
        DWORD Reserved2[2];
        DWORD DllBase;

        // NOT SUPPORTED in WINDOWS XP!
        DWORD EntryPoint;
        DWORD Reserved3;
        UNICODE_STRING FullDllName;
        BYTE Reserved4[8];
        DWORD Reserved5[3];
        union {
            ULONG CheckSum;
            DWORD Reserved6;
        };
        ULONG TimeDateStamp;
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

}

#endif /* WINXPSTRUCT_H */

