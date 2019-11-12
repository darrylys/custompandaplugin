#ifndef TRACER_H
#define TRACER_H

#include <stdint.h>
#include <cstdlib> // NULL 

#define TRC_BIT_ERROR 	(1)
#define TRC_BIT_WARN	(1 << 1)
#define TRC_BIT_INFO	(1 << 2)
#define TRC_BIT_DEBUG	(1 << 3)

namespace tracer {
	
	typedef struct _ENV_MIXIN {
		uint64_t asid;
		uint32_t pid;
		uint32_t tid;
		uint64_t instrcnt;
		uint64_t pc;
	} ENV_MIXIN;
	
	/**
	 * @class ITrcEnv
	 * @author darryl
	 * @date 25/03/19
	 * @file Tracer.cpp
	 * @brief Allows for trace to obtain env specific info
	 */
	class ITrcEnv {
	public:
		ITrcEnv(){}
		virtual ~ITrcEnv(){}
		
		/**
		 * @brief 
		 * @param out parameters to be filled
		 * @param param any object
		 * @return 
		 */
		virtual bool get_mixin(ENV_MIXIN& out, void* param) = 0;
	};
	
	void TrcInit(const char * debug_file_name, uint32_t active_trc_bits, ITrcEnv* p_env = NULL);
	
	void TrcTrace(uint32_t trc_bit, const char * format, ...);
	
	void ErrTrace(const char* file, uint32_t line, uint32_t err_code, const char * format, ...);
	
	void TrcTrace(void* p, uint32_t trc_bit, const char * format, ...);
	
	void ErrTrace(void* p, const char* file, uint32_t line, uint32_t err_code, const char * format, ...);
	
	void TrcClose();
	
	bool IsTrcActive(uint32_t trc_bit);
	
}

#endif // TRACER_H
