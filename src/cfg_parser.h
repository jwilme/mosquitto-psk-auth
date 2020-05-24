#pragma once 

#define MAX_STRING_LEN 	200
#define MAX_TOKEN_LEN 	100

enum CFG_ReturnCode{
	CFG_SUCCESS = 0,
	CFG_ERROR = 1
};

/*
 * Function: configure_plugin
 *
 * This functions opens and reads a configuration file and set the DB_instance 
 * and a DB_setting structure consequently.
 *
 * Parameters:
 * 	filename:	A string containing an absolute or relative file to an 
 * 			auth plugin configuration file
 * 	db_i:		A pointer to an allocated DB_instance structure that 
 * 			needs to be initialized.
 *
 * Returns:
 * 	CFG_SUCCESS if both the structures have been properly initialized
 * 	CFG_ERROR if the configuration could not be opened contained errors.
 * 
 */
int configure_plugin(const char *filename, struct DB_instance *db_i);
