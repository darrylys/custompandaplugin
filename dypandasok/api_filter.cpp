#include "Tracer.h"

#include "api_filter.h"
#include <assert.h>

#include <string>
#include <cstring>

namespace api_filter {
	const char * api_group_to_string(api_group group) {
		switch (group) {
		//case API_GROUP_NONE:
		//	return "None";
		
		case API_GROUP_GETCOMMANDLINE:
			return "GetCommandLine";

		case API_GROUP_GETMODULEHANDLE:
			return "GetModuleHandle";

		case API_GROUP_GETVERSION:
			return "GetVersion";

		case API_GROUP_MESSAGEBOX:
			return "MessageBox";

		case API_GROUP_OTHERS:
			return "Others";

		default:
			assert(false);
		}
		return NULL;
	}

	api_group classify_api(const char * api_name) {
		if (::strncmp(api_name, "GetVersion", 10) == 0) {
			return API_GROUP_GETVERSION;
		} else if (::strncmp(api_name, "GetCommandLine", 14) == 0) {
			return API_GROUP_GETCOMMANDLINE;
		} else if (::strncmp(api_name, "GetModuleHandle", 15) == 0) {
			return API_GROUP_GETMODULEHANDLE;
		} else if (::strncmp(api_name, "MessageBox", 10) == 0) {
			return API_GROUP_MESSAGEBOX;
		} else {
			return API_GROUP_OTHERS;
		}
	}
}