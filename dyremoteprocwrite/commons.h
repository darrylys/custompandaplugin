#ifndef COMMONS_H
#define COMMONS_H

#include <string>

#include "common_types.h"

#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plugin_plugin.h"

//#define COMMON_CONFIG_PARAM_TARGET_ASID_CSV 	"asid-csv"
//#define COMMON_CONFIG_PARAM_TARGET_PID_CSV		"pid-csv"
//#define COMMON_CONFIG_PARAM_CSV_SEPARATOR 		('|')
//#define COMMON_CONFIG_PARAM_START_ANALYSIS_ADDR	"start-addr"
//#define COMMON_CONFIG_PARAM_END_ANALYSIS_ADDR	"end-addr"
#define COMMON_CONFIG_PARAM_TRCBIT				"trcbit"

void hard_check_os_windows_7_x86();

bool soft_check_os_windows_7_x86();

target_ulong get_pid(CPUState* env);

target_ulong get_tid(CPUState* env);

target_ulong find_caller_in_process_module(CPUState* env);

target_ulong process_handle_to_pid(CPUState* env, target_ulong handle);

/**
 * Reads zero-terminated wide (2 byte) character string from guest.
 * @param cpu
 * @param buf
 * @param maxlen
 * @param guest_addr
 * @return 
 */
uint32_t guest_wzstrncpy(CPUState *cpu, uint16_t *buf, size_t maxlen, target_ulong guest_addr);

/**
 * Reads zero-terminated single byte character string from guest
 * @param cpu
 * @param buf
 * @param maxlen
 * @param guest_addr
 * @return 
 */
uint32_t guest_zstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr);


/**
 * Reads possibly non zero-terminated wide (2 byte) character string from guest.
 * @param cpu
 * @param buf
 * @param nRead is number of characters read
 * @param guest_addr
 * @return 
 */
uint32_t guest_wbstrncpy(CPUState *cpu, uint16_t *buf, int nRead, target_ulong guest_addr);

/**
 * Reads possibly non zero-terminated single byte character string from guest
 * @param cpu
 * @param buf
 * @param nRead is number of characters read
 * @param guest_addr
 * @return 
 */
uint32_t guest_bstrncpy(CPUState *cpu, char *buf, int nRead, target_ulong guest_addr);

/**
 * @brief Extracting string from OBJECT_ATTRIBUTE struct
 * for wide char, if the wide char is ASCII printable (0x20 to 0x7e), it is converted to char, 
 * otherwise, it prints the hex in format \\xXXXX, no leading zeros, if any
 * 
 * @param cpu
 * @param addr
 * @param out
 * @return 
 */
bool extract_string_from_object_attributes(CPUState* cpu, target_ulong addr, std::string& out);

/**
 * @brief checks if ch is ascii printable (0x20 <= ch <= 0xfe)
 * @param ch
 * @return 
 */
bool is_ascii_printable(uint32_t ch);

#endif