/*
 * WINDOWS XP SP3 x86
 */

/* 
 * File:   winxphdr.h
 * Author: darryl
 *
 * Created on April 27, 2017, 9:52 AM
 */

#ifndef WINXPHDR_H
#define WINXPHDR_H

// GDT
#define KMODE_FS           0x030 // Segment number of FS in kernel mode

// KPCR
#define KPCR_CURTHREAD_OFF 0x124 // _KPCR.PrcbData.CurrentThread
#define KPCR_IDLETHRAD_OFF 0x12c // _KPCR.PrcbData.IdleThread
#define KPCR_KDVERSIONBLOCK_OFF 0x034 // _KPCR.KdVersionBlock // only available for XP and up

// ETHREADKPCR_
#define ETHREAD_EPROC_OFF  0x220 // _ETHREAD.ThreadsProcess

// _ETHREAD.Tcb.ServiceTable. Should be pointing to KiServiceTable struct in ntoskrnl.exe
#define ETHREAD_TCB_SERVICETABLE_OFF 0xe0

// from EPROCESS
#define EPROC_TYPE_OFF     0x000 // _EPROCESS.Pcb.Header.Type
#define EPROC_SIZE_OFF     0x002 // _EPROCESS.Pcb.Header.Size
#define EPROC_TYPE          0x03 // Value of Type
#define EPROC_SIZE          0x1b // Value of Size
#define EPROC_DTB_OFF      0x018 // _EPROCESS.Pcb.DirectoryTableBase
#define EPROC_PID_OFF      0x084 // _EPROCESS.UniqueProcessId
#define EPROC_LINKS_OFF    0x088 // _EPROCESS.ActiveProcessLinks
#define EPROC_LINKS_FLINK_OFF    EPROC_LINKS_OFF // _EPROCESS.ActiveProcessLinks.Flink
#define EPROC_LINKS_BLINK_OFF    0x08c // _EPROCESS.ActiveProcessLinks.Blink
#define EPROC_PPID_OFF     0x14c // _EPROCESS.InheritedFromUniqueProcessId
#define EPROC_SESSIONLINKS_OFF     0x0b4 // _EPROCESS.SessionProcessLinks
#define EPROC_OBJECTTABLE_OFF      0x0c4 // _EPROCESS.ObjectTable
#define EPROC_VADROOT_OFF      0x11c // _EPROCESS.VadRoot
#define EPROC_NAME_OFF     0x174 // _EPROCESS.ImageFileName
#define EPROC_PEB_OFF      0x1b0 // _EPROCESS.Peb
#define EPROC_ACTIVETHREADS_OFF      0x1a0 // _EPROCESS.ActiveThreads

// PEB
#define PEB_IMAGEBASEADDR_OFF 0x008 // _PEB.ImageBaseAddress // this is not reliable. the values are weird.
#define PEB_LDR_OFF        0x00c // _PEB.Ldr

// LDR_DATA_ENTRY (PEB points here)
#define LDR_DATA_ENTRY_MEM_LINKS_OFF  0x014 // _PEB_LDR_DATA.InMemoryOrderModuleList

// LDR_DATA_TABLE_ENTRY
#define LDR_TABLE_MEM_LINKS_OFF  0x008 // _LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks
#define LDR_TABLE_BASE_OFF       0x018 // _LDR_DATA_TABLE_ENTRY.DllBase
#define LDR_TABLE_ENTRYPOINT_OFF 0x01c // _LDR_DATA_TABLE_ENTRY.EntryPoint
#define LDR_TABLE_SIZE_OFF       0x020 // _LDR_DATA_TABLE_ENTRY.SizeOfImage
#define LDR_TABLE_FILENAME_OFF   0x024 // _LDR_DATA_TABLE_ENTRY.FullDllName
#define LDR_TABLE_BASENAME_OFF   0x02c // _LDR_DATA_TABLE_ENTRY.BaseDllName

// _DBGKD_GET_VERSION32
#define DBGKD_GET_VER32_PSLOADEDMODULELIST_OFF 0x00c


// _DBGKD_GET_VERSION64
#define DBGKD_GET_VER64_PSLOADEDMODULELIST_OFF 0x018
#define DBGKD_GET_VER64_DEBUGGERDATALIST_OFF 0x020


// _KDDEBUGGER_DATA64
#define KDDEBUGGER_DATA64_FLINK_OFF 0x000
#define KDDEBUGGER_DATA64_BLINK_OFF 0x008
#define KDDEBUGGER_DATA64_TAG_OFF 0x010
#define KDDEBUGGER_DATA64_SIZE_OFF 0x014


// _STSTEM_SERVICE_TABLE (SSDT)
#define SSDT_SERVICE_TABLE_OFF 0x00
#define SSDT_COUNTER_TABLE_OFF 0x04
#define SSDT_SERVICE_LIMIT_OFF 0x08
#define SSDT_ARGUMENT_TABLE_OFF 0x0c

// Windows XP
// KeServiceDescriptorTableShadow := KeServiceDescriptorTable - 0x40
#define SSDT_SERVICE_TBL_SHADOW_FROM_TBL_OFF (-0x40)

///*
// * WINDOWS x86 DEBUGGER STUFF from wdbgexts.h WINDDK
// * warning on pointer types. They're probably 8 bytes (should be 4 bytes in guest)
// */
//
//typedef uint16_t USHORT;
//typedef uint32_t ULONG;
//typedef int16_t SHORT;
//
//typedef struct _LSA_UNICODE_STRING {
//  /*+0x000*/ USHORT Length;
//  /*+0x002*/ USHORT MaximumLength;
//  /*+0x004*/ ULONG  Buffer;
//  /*+0x008*/
//} UNICODE_STRING;
//
//typedef struct _LIST_ENTRY {
//    /*+0x000*/ ULONG Flink;
//    /*+0x004*/ ULONG Blink;
//    /*+0x008*/
//} LIST_ENTRY, LIST_ENTRY32;
//
//// this seems correct...
//struct LDR_MODULE {
//  /*+0x000*/ LIST_ENTRY InLoadOrderModuleList;
//  /*+0x008*/ LIST_ENTRY InMemoryOrderModuleList;
//  /*+0x010*/ LIST_ENTRY InInitializationOrderModuleList;
//  /*+0x018*/ ULONG BaseAddress;
//  /*+0x01c*/ ULONG EntryPoint;
//  /*+0x020*/ ULONG SizeOfImage;
//  /*+0x024*/ UNICODE_STRING FullDllName;
//  /*+0x02c*/ UNICODE_STRING BaseDllName;
//  /*+0x034*/ ULONG Flags;
//  /*+0x038*/ SHORT LoadCount;
//  /*+0x03a*/ SHORT TlsIndex;
//  /*+0x03c*/ LIST_ENTRY HashTableEntry;
//  /*+0x044*/ ULONG TimeDateStamp;
//};
//
////
//// The following structure has changed in more than pointer size.
////
//// This is the version packet for pre-NT5 Beta 2 systems.
//// For now, it is also still used on x86
////
//typedef struct _DBGKD_GET_VERSION32 {
//    /*+0x000*/ USHORT  MajorVersion;
//    /*+0x002*/ USHORT  MinorVersion;
//    /*+0x004*/ USHORT  ProtocolVersion;
//    /*+0x006*/ USHORT  Flags;
//    /*+0x008*/ ULONG   KernBase;
//    /*+0x00c*/ ULONG   PsLoadedModuleList; // points to LDR_MODULE struct (probably, must be tested)
//
//    /*+0x010*/ USHORT  MachineType;
//
//    //
//    // help for walking stacks with user callbacks:
//    //
//
//    //
//    // The address of the thread structure is provided in the
//    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
//    // the thread structure to the pointer to the kernel stack frame
//    // for the currently active usermode callback.
//    //
//
//    /*+0x012*/ USHORT  ThCallbackStack;            // offset in thread data
//
//    //
//    // these values are offsets into that frame:
//    //
//
//    /*+0x014*/ USHORT  NextCallback;               // saved pointer to next callback frame
//    /*+0x016*/ USHORT  FramePointer;               // saved frame pointer
//
//    //
//    // Address of the kernel callout routine.
//    //
//
//    /*+0x018*/ ULONG   KiCallUserMode;             // kernel routine
//
//    //
//    // Address of the usermode entry point for callbacks.
//    //
//
//    /*+0x01c*/ ULONG   KeUserCallbackDispatcher;   // address in ntdll
//
//    //
//    // DbgBreakPointWithStatus is a function which takes a ULONG argument
//    // and hits a breakpoint.  This field contains the address of the
//    // breakpoint instruction.  When the debugger sees a breakpoint
//    // at this address, it may retrieve the argument from the first
//    // argument register, or on x86 the eax register.
//    //
//
//    /*+0x020*/ ULONG   BreakpointWithStatus;       // address of breakpoint
//
//    //
//    // Components may register a debug data block for use by
//    // debugger extensions.  This is the address of the list head.
//    //
//
//    /*+0x024*/ ULONG   DebuggerDataList; // we probably want this pointer
//
//} DBGKD_GET_VERSION32;
//
//
////
//// This is the debugger data packet for pre NT5 Beta 2 systems.
//// For now, it is still used on x86
////
//
//typedef struct _DBGKD_DEBUG_DATA_HEADER32 {
//
//    LIST_ENTRY32 List;
//    ULONG           OwnerTag;
//    ULONG           Size;
//
//} DBGKD_DEBUG_DATA_HEADER32;
//
//typedef struct _KDDEBUGGER_DATA32 {
//
//    DBGKD_DEBUG_DATA_HEADER32 Header;
//    ULONG   KernBase;
//    ULONG   BreakpointWithStatus;       // address of breakpoint
//    ULONG   SavedContext;
//    USHORT  ThCallbackStack;            // offset in thread data
//    USHORT  NextCallback;               // saved pointer to next callback frame
//    USHORT  FramePointer;               // saved frame pointer
//    USHORT  PaeEnabled:1;
//    ULONG   KiCallUserMode;             // kernel routine
//    ULONG   KeUserCallbackDispatcher;   // address in ntdll
//
//    ULONG   PsLoadedModuleList;
//    ULONG   PsActiveProcessHead;
//    ULONG   PspCidTable;
//
//    ULONG   ExpSystemResourcesList;
//    ULONG   ExpPagedPoolDescriptor;
//    ULONG   ExpNumberOfPagedPools;
//
//    ULONG   KeTimeIncrement;
//    ULONG   KeBugCheckCallbackListHead;
//    ULONG   KiBugcheckData;
//
//    ULONG   IopErrorLogListHead;
//
//    ULONG   ObpRootDirectoryObject;
//    ULONG   ObpTypeObjectType;
//
//    ULONG   MmSystemCacheStart;
//    ULONG   MmSystemCacheEnd;
//    ULONG   MmSystemCacheWs;
//
//    ULONG   MmPfnDatabase;
//    ULONG   MmSystemPtesStart;
//    ULONG   MmSystemPtesEnd;
//    ULONG   MmSubsectionBase;
//    ULONG   MmNumberOfPagingFiles;
//
//    ULONG   MmLowestPhysicalPage;
//    ULONG   MmHighestPhysicalPage;
//    ULONG   MmNumberOfPhysicalPages;
//
//    ULONG   MmMaximumNonPagedPoolInBytes;
//    ULONG   MmNonPagedSystemStart;
//    ULONG   MmNonPagedPoolStart;
//    ULONG   MmNonPagedPoolEnd;
//
//    ULONG   MmPagedPoolStart;
//    ULONG   MmPagedPoolEnd;
//    ULONG   MmPagedPoolInformation;
//    ULONG   MmPageSize;
//
//    ULONG   MmSizeOfPagedPoolInBytes;
//
//    ULONG   MmTotalCommitLimit;
//    ULONG   MmTotalCommittedPages;
//    ULONG   MmSharedCommit;
//    ULONG   MmDriverCommit;
//    ULONG   MmProcessCommit;
//    ULONG   MmPagedPoolCommit;
//    ULONG   MmExtendedCommit;
//
//    ULONG   MmZeroedPageListHead;
//    ULONG   MmFreePageListHead;
//    ULONG   MmStandbyPageListHead;
//    ULONG   MmModifiedPageListHead;
//    ULONG   MmModifiedNoWritePageListHead;
//    ULONG   MmAvailablePages;
//    ULONG   MmResidentAvailablePages;
//
//    ULONG   PoolTrackTable;
//    ULONG   NonPagedPoolDescriptor;
//
//    ULONG   MmHighestUserAddress;
//    ULONG   MmSystemRangeStart;
//    ULONG   MmUserProbeAddress;
//
//    ULONG   KdPrintCircularBuffer;
//    ULONG   KdPrintCircularBufferEnd;
//    ULONG   KdPrintWritePointer;
//    ULONG   KdPrintRolloverCount;
//
//    ULONG   MmLoadedUserImageList;
//
//} KDDEBUGGER_DATA32;
//
//// **********************************************************************
////
//// DO NOT CHANGE KDDEBUGGER_DATA32!!
//// ONLY MAKE CHANGES TO KDDEBUGGER_DATA64!!!
////
//// **********************************************************************

#endif /* WINXPHDR_H */

