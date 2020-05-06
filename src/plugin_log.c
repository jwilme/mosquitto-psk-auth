#include <string.h>
#include <stdarg.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"

#include "plugin_log.h"

void plugin_log(int type, char * prefix, char * fmt, ...)
{	
	int len = strlen(ftm) + 500;
	char * msg; 
	va_list va;

	msg = (char *)malloc(len * sizeof(char));	
	
	va_start(va, fmt);
	vsnprintf(msg, len, fmt, va);
	va_end(va);

	msg[len-1] = '\0';

	mosquitto_log_printf(type, "%s %s\n", prefix, msg);

	free(msg);
}
