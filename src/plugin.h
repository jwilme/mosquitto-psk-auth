#pragma once

enum Plugin_ErrorCodes{
	PLUGIN_SUCCESS = 0,
	PLUGIN_FAILURE = 1
};


#define DB_I ((struct DB_instance *)(user_data))
