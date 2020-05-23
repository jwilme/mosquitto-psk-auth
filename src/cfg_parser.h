#pragma once 

#define MAX_STRING_LEN 	200
#define MAX_TOKEN_LEN 	100

enum CFG_ReturnCode{
	CFG_SUCCESS = 0,
	CFG_ERROR = 1
};

int configure_plugin(const char *filename, struct DB_instance *db_i);
