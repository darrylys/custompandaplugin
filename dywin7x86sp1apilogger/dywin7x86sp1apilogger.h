#ifndef DYWIN7X86SP1_APILOGGER_H
#define DYWIN7X86SP1_APILOGGER_H

#include <string>

#define S_W_OK (0)
#define E_W_ERR (-1)

typedef struct _API_INFO {
	std::string fn_name;
	std::string module_name;
	std::string module_file;
	target_ulong module_base;
	target_ulong fn_rva;
	target_ulong offset;
	target_ulong module_size;
	// add later on.
	
	_API_INFO()
	:fn_name(),
	module_name(),
	module_file(),
	module_base(0),
	fn_rva(0),
	offset(0),
	module_size(0)
	{}
	
} API_INFO;

#endif