#ifndef API_FILTER_H
#define API_FILTER_H

namespace api_filter {

	enum api_group {
		API_GROUP_NONE = 0,
		API_GROUP_GETVERSION,
		API_GROUP_GETCOMMANDLINE,
		API_GROUP_GETMODULEHANDLE,
		API_GROUP_MESSAGEBOX,
		API_GROUP_OTHERS,
		API_GROUP_LENGTH
	};

	const char * api_group_to_string(api_group group);

	api_group classify_api(const char * api_name);

}

#endif