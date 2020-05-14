#include <termios.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

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


struct DB_instance * db_i;
char * psk_master_key;

/*
 * Function: prompt_password
 *
 * This internal function function prompts for a password on the standard input, after
 * it has disabled the echo of the stdin. After a line is fetched and stored, it
 * re-enables the echo on the stdin.
 *
 * Parameters:
 * 	password:	An allocated buffer where the line fetched from the
 * 			standard input will be stored
 *
 * Returns:
 * 	-1 if a line could not be fetched or the echo could be turned off
 * 	Otherwise, it returns the number of characters fetched 
 */
int _prompt_password(char ** password)
{	
	struct termios old, new;
	int nread;
	long unsigned int buffsize = MAX_CREDENTIAL_SIZE;

	if(tcgetattr((uint64_t)stdin, &old) != 0)
		return -1;

	new = old;
	new.c_lflag &= ~ECHO;
	if(tcsetattr((uint64_t)stdin, TCSAFLUSH, &new) != 0)
		return -1;

	nread = getline(password, &buffsize, stdin);

	(void) tcsetattr((uint64_t)stdin, TCSAFLUSH, &old);

	return nread;
}

int auth_init(struct DB_instance *db_inst){
	db_i = db_inst;	
	db_i->init();

	psk_master_key = (char *)malloc(sizeof(char *) * KEY_LEN);	
	if(!psk_master_key){
		auth_log_error("Could not allocate memory for the"
				"psk_master_key");
		return AUTH_FAILURE;
	}

	return AUTH_SUCCESS;
}

int auth_connect_db()
{
	/* Prompt for Username and Password and Attempt to Connect to the DB */
	char * un = (char *)malloc(MAX_CREDENTIAL_SIZE * sizeof(char));
	char * pwd = (char *)malloc(MAX_CREDENTIAL_SIZE * sizeof(char));

	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			auth_log_error("Max number of MySQL Authentication "
					"attempts reached");
			free(un);
			free(pwd);
			return AUTH_DENIED;
		}

		printf("DB Username : ");
		long unsigned int un_len = MAX_CREDENTIAL_SIZE;
		int rc_un = getline(&un, &un_len, stdin);

		printf("DB Password : ");
		int rc_pw = _prompt_password(&pwd); 
			
		if(rc_un <= 0 || rc_pw <= 0){
			auth_log_error("Unable to prompt for the password or "
					"for the username");	
			continue;
		} 
		
		else if(!db_i->connect((const char *)un, (const char *)pwd)){
			break;
		}

		auth_log_error("Bad username and/or password");
	}

	free(un);
	free(pwd);

	db_i->prepare_statements();
	return AUTH_SUCCESS;
}

int auth_master_psk()
{
	/* Prompt for Password and Check that it is the correct key */
	char *pwd = (char *)malloc(MAX_CREDENTIAL_SIZE * sizeof(char));

	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			auth_log_error("Max number of PSK Authentication "
					"attempts reached");
			free(pwd);
			return AUTH_DENIED;
		}
	
		printf("Password :");	
		if(_prompt_password(&pwd) < 0){
			auth_log_error("Unable to prompt for the password");	
			continue;
		}

		if(auth_client(MASTER_PSK_USERNAME, pwd)) break;
	}

	/* Generate and store the PSK Master Key */
	char salt[SALT_LEN + 1]; 
	db_i->get_salt(MASTER_PSK_USERNAME, salt);

	int err = compute_master_key(pwd, salt, psk_master_key);

	free(pwd);	

	if(err){
		auth_log_error("Could not generate the PSK Master Key");
		return AUTH_FAILURE;
	} else {
		auth_log_info("Successfuly generated the PSK Master Key");
		return AUTH_SUCCESS;
	}
}

int auth_client(const char * username, const char * password)
{
	int return_code = 0;
	long long int result;

	char *salt_buf = (char *)malloc(sizeof(char) * (SALT_LEN+1));
	char *hash_buf = (char *)malloc(sizeof(char) * (HASH_LEN+1));

	if(db_i->get_salt(username, salt_buf))
		return_code = AUTH_FAILURE;
	
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

int auth_get_psk(const char * identity, char * psk_key)
{

	char *init_vector = (char *) malloc(sizeof(char) * IV_LEN); 
	char *cyphered_key = (char *) malloc(sizeof(char) * KEY_LEN);
	
	if(db_i->fetch_psk_key(identity, init_vector, cyphered_key)){ 
		free(cyphered_key);
		free(init_vector);

		return AUTH_FAILURE;
	} 
	
	int decypher_error = decypher_key(psk_master_key, cyphered_key, init_vector, psk_key);
	free(cyphered_key);
	free(init_vector);

	return decypher_error ? AUTH_FAILURE: AUTH_SUCCESS;	
}

int auth_disconnect(){
	db_i->close_statements();
	db_i->disconnect();

	free(psk_master_key);	
	return AUTH_SUCCESS;
}

int auth_cleanup(){
	db_i->cleanup();
	return AUTH_SUCCESS;
}
