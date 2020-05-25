#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "db_common.h"
#include "crypto.h"
#include "auth.h"
#include "plugin_log.h"

#define LOG_AUTH_ERROR_PREFIX 		"[AUTH - ERROR] ::"
#define LOG_AUTH_WARNING_PREFIX 	"[AUTH - WARNING] ::"
#define LOG_AUTH_INFO_PREFIX 		"[AUTH - INFO] ::"

#define auth_log_error(...) \
	plugin_log(LOG_AUTH_ERROR_PREFIX, __VA_ARGS__)

#define auth_log_warning(...) \
	plugin_log(LOG_AUTH_WARNING_PREFIX, __VA_ARGS__)

#define auth_log_info(...) \
	plugin_log(LOG_AUTH_INFO_PREFIX, __VA_ARGS__)


struct DB_instance *db_i;

int auth_init(struct DB_instance *db_inst){
	db_i = db_inst;	
	return AUTH_SUCCESS;
}

int auth_connect_db()
{
	if(db_i->connect())
		return AUTH_FAILURE;
	return AUTH_SUCCESS;
}

#ifdef TLS_PSK
int auth_master_psk()
{
	return AUTH_SUCCESS;
}
#endif

int auth_client(const char * username, const char * password)
{
	int return_code = 0;
	long long int result;

	char *salt_buf = (char *)malloc(sizeof(char) * (SALT_LEN+1));
	char *hash_buf = (char *)malloc(sizeof(char) * (HASH_LEN*2));

	int ret = db_i->get_salt(username, salt_buf);
	if(ret == DB_FAILURE)
		return_code = AUTH_FAILURE;

	else if(ret == DB_DENIED)
		return_code = AUTH_DENIED;	

	else if(hash_password(password, salt_buf, hash_buf))
		return_code = AUTH_FAILURE;

	else if (db_i->pw_check(username, hash_buf, &result))
		return_code = AUTH_FAILURE;

	free(salt_buf);
	free(hash_buf);

	if(return_code) 
		return return_code;
	
	return (result == 1) ? AUTH_SUCCESS : AUTH_DENIED;
}

#ifdef TLS_PSK
int auth_get_psk(const char * identity, char * psk_key)
{
	(void)(identity);
	(void)(psk_key);
	return AUTH_FAILURE;
}
#endif

int auth_disconnect(){
	db_i->disconnect();
	return AUTH_SUCCESS;
}

int auth_cleanup(){
	db_i->cleanup();
	return AUTH_SUCCESS;
}
