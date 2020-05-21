#pragma once

enum Plugin_ErrorCodes{
	PLUGIN_SUCCESS = 0,
	PLUGIN_FAILURE = 1
};

#define LOG_PLUGIN_FATAL 	"[PLUGIN - FATAL] ::"
#define LOG_PLUGIN_ERROR 	"[PLUGIN - ERROR] ::"
#define LOG_PLUGIN_WARNING 	"[PLUGIN - WARNING] ::"
#define LOG_PLUGIN_INFO 	"[PLUGIN - INFO] ::"

#define plugin_log_fatal(...) \
	plugin_log(LOG_PLUGIN_FATAL, __VA_ARGS__)

#define plugin_log_error(...) \
	plugin_log(LOG_PLUGIN_ERROR, __VA_ARGS__)

#define plugin_log_warning(...) \
       	plugin_log(LOG_PLUGIN_WARNING, __VA_ARGS__)

#define plugin_log_info(...) \
	plugin_log(LOG_PLUGIN_INFO, __VA_ARGS__) 

