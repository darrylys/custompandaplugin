#ifndef DYWIN7X86SP1_APILOGGER_INT_FNS_H
#define DYWIN7X86SP1_APILOGGER_INT_FNS_H

/**
 * @brief gets information about API function
 * @param cpu
 * @param pc the starting address of API function
 * @param api_info output struct
 * @return 0 if API is found in csv database, -1 otherwise
 */
int get_api_info(CPUState* cpu, target_ulong pc, API_INFO* api_info);

#endif