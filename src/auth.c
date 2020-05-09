#include <termios.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>

#include "mysql.h"
#include "crypto.h"

#define LOG_AUTH_ERROR 		"[AUTH - ERROR] ::"
#define LOG_AUTH_WARNING 	"[AUTH - WARNING] ::"
#define LOG_AUTH_INFO 		"[AUTH - INFO] ::"

#define auth_log_error(char * fmt, ...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_AUTH_ERROR, char *fmt, ...)

#define auth_log_warning(char * fmt, ...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_AUTH_WARNING, char *fmt, ...)

#define auth_log_info(char * fmt, ...) \
	plugin_log(MOSQ_LOG_INFO, LOG_AUTH_INFO, char *fmt, ...)

char * psk_key;

int psk_master_auth(const char * password, char * out_key)
{
	char * username = MASTER_PSK_USERNAME;

	switch(unpwd_client_auth( (const char *) username, password)){

	case(AUTH_SUCCESS):
		if(compute_master_key(password, out_key))
			return AUTH_FAILURE;

		return AUTH_SUCCESS; 

	case(AUTH_DENIED):
		return AUTH_DENIED;

	case(AUTH_FAILURE):
		return AUTH_FAILURE;

	}	
}

int unpwd_client_auth(const char * username, const char * password)
{
	int return_code = 0;
	long long int result;

	char *salt_buf = (char *)malloc(sizeof(char) * (SALT_LEN+1));
	char *hash_buf = (char *)malloc(sizeof(char) * (HASH_LEN+1));

	if(fetch_salt(username, salt_buf))
		return_code = AUTH_FAILURE;
	
	else if(hash_password(password, salt_buf, hash_buf))
		return_code = AUTH_FAILURE;

	else if (pw_check(username, hash_buff, &result))
		return_code = AUTH_FAILURE;

	free(salt_buf);
	free(hash_buf);

	if(return_code) 
		return return_code;
	
	return (result == 1) ? AUTH_SUCCESS : AUTH_DENIED;
}


int psk_client_auth(const char * identity, char * psk_key)
{
	int return_code = 0;

	char *init_vector = (char *) malloc(sizeof(char) * IV_LEN); 
	char *cyphered_key = (char *) malloc(sizeof(char) * KEY_LEN);
	
	if(fetch_psk_key(identity, init_vector, cyphered_key)){ 
		free(cyphered_key);
		free(init_vector);

		return AUTH_FAILURE;
	} 
	
	int decypher_error = decypher_key(master_key, cyphered_key, init_vector, psk_key);
	free(cyphered_key);
	free(init_vector);

	return decypher_error ? AUTH_FAILURE: AUTH_SUCCESS;	
}

int get_pass(const char * , char *){

}
