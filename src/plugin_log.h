#pragma once

/*
 * Function: plugin_log
 *
 * This function prints a message log and appends a prefix to that
 * message.
 *
 * Parameters:
 * 	prefix:		The prefix to append at the beginning of the log
 * 			message
 * 	fmt:		A string using printf-like formatting. The following
 * 			arguments are the same as if calling the printf function 
 */
void plugin_log(char * prefix, char * fmt, ...);
