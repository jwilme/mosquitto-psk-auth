#include <termios.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>

#include "mysql.h"
#include "crypto.h"

#define LOG_AUTH_ERROR_PREFIX 		"[AUTH - ERROR] ::"
#define LOG_AUTH_WARNING_PREFIX 	"[AUTH - WARNING] ::"
#define LOG_AUTH_INFO_PREFIX 		"[AUTH - INFO] ::"

#define auth_log_error(char * fmt, ...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_AUTH_ERROR_PREFIX, char *fmt, ...)

#define auth_log_warning(char * fmt, ...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_AUTH_WARNING_PREFIX, char *fmt, ...)

#define auth_log_info(char * fmt, ...) \
	plugin_log(MOSQ_LOG_INFO, LOG_AUTH_INFO_PREFIX, char *fmt, ...)

int db_connection(void *user_data, const char *username, 
		const char *table_name, const char* db_path)
{
	/* Prompt for Password and Attempt to Connect to the DB */
	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			auth_log_error("Max number of MySQL Authentication "
					"attempts reached");
			return AUTH_DENIED;
		}

		char * db_password;
		if(prompt_password(&db_password) < 0){
			auth_log_error("Unable to prompt for the password");	
			continue
		} 
		
		else if(mysql_connect(user_data, username) == DB_SUCCESS){
			break;
		}
	       
		else{
			free(db_password);	
		}
	}

	free(db_password);
	return AUTH_SUCCESS;
}

int psk_init(char * psk_generated_key)
{
	/* Prompt for Password and Check that it is the correct key */
	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			auth_log_error("Max number of PSK Authentication "
					"attempts reached");
			return AUTH_DENIED;
		}

		char * psk_password;
		if(prompt_password(&psk_password) < 0){
			auth_log_error("Unable to prompt for the password");	
			continue;
		}

		if(unpwd_client_auth(MASTER_PSK_USERNAME, psk_password)) break;
		else free(psk_password);
	}

	/* Generate and store the PSK Master Key */
	char salt[SALT_LEN + 1]; 
	fetch_salt(MASTER_PSK_USERNAME, psk_salt);

	int err = compute_master_key(psk_password, salt, out_key);

	free(psk_password);	

	if(err){
		auth_log_error("Could not generate the PSK Master Key");
		return AUTH_FAILURE;
	} else {
		auth_log_info("Successfuly generated the PSK Master Key");
		return AUTH_SUCCESS;
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

int prompt_password(char ** password)
{	
	struct termios old, new;
	int nread;

	if(tcgetattr(stdin, &old) != 0)
		return -1;

	new = old;
	new.c_lflag &= ~ECHO;
	if(tcsetattr(stdin, TCSAFLUSH, &new) != 0)
		return -1;

	nread = getline(lineptr, MAX_PASSWORD_SIZE, stdin);

	(void) tcsetattr(stdin, TCSAFLUSH, &old);

	return nread;
}
