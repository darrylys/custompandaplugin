#include "Tracer.h"
#include <cstdio>
#include <cstdarg>

#define TRC_MAX_BUFFER (256)
#define ERR_MAX_BUFFER (1024)

namespace tracer {
	
	FILE* g_debug_file = NULL;
	uint32_t g_active_trc_bits = 0;
	bool is_initialized = false;
	ITrcEnv* p_trc_env = NULL;
	
	void TrcInit(const char * debug_file_name, uint32_t active_trc_bits, ITrcEnv* p_env) {
		if (!is_initialized) {
			g_debug_file = fopen(debug_file_name, "w");
			g_active_trc_bits = active_trc_bits;
			p_trc_env = p_env;
			is_initialized = true;
		}
	}
	
	void PrintMixin(void* p) {
		if (p_trc_env != NULL) {
			ENV_MIXIN mixin;
			if (p_trc_env->get_mixin(mixin, p)) {
				fprintf(g_debug_file, "%016lx %u %u %lu %lx\t", mixin.asid, 
						mixin.pid, mixin.tid, mixin.instrcnt, mixin.pc);
			}
		}
	}
	
	void VaTrcTrace(void* p, uint32_t trc_bit, const char * format, va_list args) {
		//va_list args;
		//va_start (args, format);
		const char * label;
		switch (trc_bit) {
			case TRC_BIT_DEBUG:
			label = "[debug]";
			break;
			
			case TRC_BIT_WARN:
			label = "[warn]";
			break;
			
			case TRC_BIT_ERROR:
			label = "[error]";
			break;
			
			case TRC_BIT_INFO:
			default:
			label = "[info]";
			break;
		}
		PrintMixin(p);
		fprintf(g_debug_file, "%s\t\t", label);
		::vfprintf(g_debug_file, format, args);
		//va_end (args);
		fprintf(g_debug_file, "\n");
	}
	
	void TrcTrace(uint32_t trc_bit, const char * format, ...) {
		if (IsTrcActive(trc_bit) && g_debug_file != NULL) {
			va_list args;
			va_start (args, format);
			VaTrcTrace(NULL, trc_bit, format, args);
			va_end (args);
		}
	}
	
	void TrcTrace(void* p, uint32_t trc_bit, const char * format, ...) {
		if (IsTrcActive(trc_bit) && g_debug_file != NULL) {
			va_list args;
			va_start (args, format);
			VaTrcTrace(p, trc_bit, format, args);
			va_end (args);
		}
	}
	
	void VaErrTrace(void* p, const char* file, uint32_t line, uint32_t err_code, 
	const char * format, va_list args) {
		PrintMixin(p);
		fprintf(g_debug_file, "FILE: %s\nLINE: %u\nERR: %08x\n", file, line, err_code);
		::vfprintf(g_debug_file, format, args);
		fprintf(g_debug_file, "\n");
	}
	
	void ErrTrace(void* p, const char* file, uint32_t line, uint32_t err_code, const char * format, ...) {
		if (g_debug_file != NULL) {
			va_list args;
			va_start (args, format);
			VaErrTrace(p, file, line, err_code, format, args);
			va_end (args);
		}
	}
	
	void ErrTrace(const char* file, uint32_t line, uint32_t err_code, const char * format, ...) {
		if (g_debug_file != NULL) {
			va_list args;
			va_start (args, format);
			VaErrTrace(NULL, file, line, err_code, format, args);
			va_end (args);
		}
	}
	
	void TrcClose() {
		if (g_debug_file) {
			fclose(g_debug_file);
		}
	}
	
	bool IsTrcActive(uint32_t trc_bit) {
		return (g_active_trc_bits & trc_bit) > 0;
	}

}