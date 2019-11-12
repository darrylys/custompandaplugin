#include "winstruct.h"

// warn: only for Windows 7 x86 machines!
#define WIN7_X86_FS_PEB_OFF 							(0x30)
#define WIN7_X86_PEB_PEBLDRDATA_OFF 					(0xc)
#define WIN7_X86_PEBLDRDATA_INLOADORDERMODULELIST_OFF 	(0xc)
#define WIN7_X86_LDRDATATABLEENTRY_SIZEOFIMAGE_OFF 		(0x20)

WIN_OFF gWindowsOffsets;

bool initvars() {
	gWindowsOffsets.fs_peb_off = WIN7_X86_FS_PEB_OFF;
	gWindowsOffsets.ldrdatatableentry_sizeofimage_off = 
			WIN7_X86_LDRDATATABLEENTRY_SIZEOFIMAGE_OFF;
	gWindowsOffsets.peb_pebldrdata_off = 
			WIN7_X86_PEB_PEBLDRDATA_OFF;
	gWindowsOffsets.pebldrdata_inloadordermodulelist_off = 
			WIN7_X86_PEBLDRDATA_INLOADORDERMODULELIST_OFF;
			
	return true;
}
