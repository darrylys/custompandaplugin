#ifndef UTILHELPER_H
#define UTILHELPER_H

#include "panda/plugin.h"

bool soft_check_os_windows_7_x86();

void hard_check_os_windows_7_x86();

bool userModeAndUserCodeOnly(CPUState *cpu, target_ulong pc, target_ulong targetAsid);

#endif