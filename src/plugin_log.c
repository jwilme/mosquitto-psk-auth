#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"

#include "plugin_log.h"


/*
 * Function: plugin_log
 *
 * This function prints a log using mosquitto's log function. The sole purpose
 * of this function is to simplify the code written. 
 *
 * Parameters: 
 * 	type:		The mosquitto log type
 * 	prefix:		A string prefix that will be appended at the beginning of the 
 * 			message
 * 	fmt: 		A string to format, takes the same form as a string given in a
 * 			printf call
 *		
 */
void plugin_log(char * prefix, char * fmt, ...)
{	
	int len = strlen(fmt) + 500;
	char * msg; 
	va_list va;

	msg = (char *)malloc(len * sizeof(char));	
	
	va_start(va, fmt);
	vsnprintf(msg, len, fmt, va);
	va_end(va);

	msg[len-1] = '\0';

	printf("%s %s\n", prefix, msg);
	free(msg);
}
