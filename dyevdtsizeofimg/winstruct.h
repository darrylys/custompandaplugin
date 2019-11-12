#ifndef __WINSTRUCT_H__
#define __WINSTRUCT_H__

#include <stdint.h>

typedef struct _WIN_OFF {
	uint32_t fs_peb_off;
	uint32_t peb_pebldrdata_off;
	uint32_t pebldrdata_inloadordermodulelist_off;
	uint32_t ldrdatatableentry_sizeofimage_off;
} WIN_OFF, *PWIN_OFF;

extern WIN_OFF gWindowsOffsets;

bool initvars();

#endif