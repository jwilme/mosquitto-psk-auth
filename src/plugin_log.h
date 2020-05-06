#pragma once

#define LOG_PLUGIN_ERROR 	"[PLUGIN - ERROR] ::"
#define LOG_PLUGIN_WARNING 	"[PLUGIN - WARNING] ::"
#define LOG_PLUGIN_INFO 	"[PLUGIN - INFO] ::"

#define LOG_MYSQL_ERROR 	"[MYSQL - ERROR] ::"
#define LOG_MYSQL_WARNING 	"[MYSQL - WARNING] ::"
#define LOG_MYSQL_INFO 		"[MYSQL - INFO] ::"

#define LOG_CRYPTO_ERROR 	"[CRYPTO - ERROR] ::"
#define LOG_CRYPTO_WARNING 	"[CRYPTO - WARNING] ::"
#define LOG_CRYPTO_INFO 	"[CRYPTO - INFO] ::"


#define plugin_log_error(char * fmt, ...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_PLUGIN_ERROR, char *fmt, ...)

#define plugin_log_warning(char * fmt, ...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_PLUGIN_WARNING, char *fmt, ...)

#define plugin_log_info(char * fmt, ...) \
	plugin_log(MOSQ_LOG_INFO, LOG_PLUGIN_INFO, char *fmt, ...)

#define mysql_log_error(char * fmt, ...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_MYSQL_ERROR, char *fmt, ...)

#define mysql_log_warning(char * fmt, ...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_MYSQL_WARNING, char *fmt, ...)

#define mysql_log_info(char * fmt, ...) \
	plugin_log(MOSQ_LOG_INFO, LOG_MYSQL_INFO, char *fmt, ...)

#define crypto_log_error(char * fmt, ...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_CRYPTO_ERROR, char *fmt, ...)

#define crypto_log_warning(char * fmt, ...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_CRYPTO_WARNING, char *fmt, ...)

#define crypto_log_info(char * fmt, ...) \
	plugin_log(MOSQ_LOG_INFO, LOG_CRYPTO_INFO, char *fmt, ...)


