#include <termios.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include "crypto.h"
#include "auth.h"
#include "plugin_log.h"

#define LOG_AUTH_ERROR_PREFIX 		"[AUTH - ERROR] ::"
#define LOG_AUTH_WARNING_PREFIX 	"[AUTH - WARNING] ::"
#define LOG_AUTH_INFO_PREFIX 		"[AUTH - INFO] ::"

#define auth_log_error(...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_AUTH_ERROR_PREFIX, __VA_ARGS__)

#define auth_log_warning(...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_AUTH_WARNING_PREFIX, __VA_ARGS__)

#define auth_log_info(...) \
	plugin_log(MOSQ_LOG_INFO, LOG_AUTH_INFO_PREFIX, __VA_ARGS__)

struct DB_instance db_i;

/*
 * Function: prompt_password
 *
 * This function function prompts for a password on the standard input, after
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

/*
 * Function: auth_init
 *
 * This function initializes all authentication structure according to the
 * given mosquitto options, and the options set in the plugin config file
 *
 * Parameters:
 *
 * Return Value:
 *
 */
int auth_init(struct mosquitto_opt *opts, int opt_count){
	memset(&db_i, 0, sizeof(db_i));
	memset(&cry_i, 0, sizeof(cry_i));

	for(int i = 0; i < opt_count; i++){
		//Read all the options passed to the plugin
	}

	//Open plugin.conf file
	//For each line, extract the option and its value
	
	return AUTH_SUCCESS;
}

/*
 * Function: auth_connect_db 
 *
 * This functions prompts for a password in the standard input, and will 
 * attempt to connect to the DB using the given credentials.
 *
 * XXX : For the moment, the username is a constant, for the future, it could
 * nice to be able to prompt for the username as well
 *
 * Return value:
 * 	AUTH_SUCCESS if the connection is established to the database
 * 	AUTH_DENIED if the connection attemp fails "RETRY_LIMITS" times
 */
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
		
		else if(!db_i.connect((const char *)un, (const char *)pwd)){
			break;
		}
	}

	free(un);
	free(pwd);

	db_i.prepare_statements();

	return AUTH_SUCCESS;
}

/*
 * Function: auth_master_psk 
 *
 * This function will generate the psk_master_key used to decypher the
 * PSK stored in the DB. It does it in three steps :
 *
 * 	1. It prompts for the psk_master_password
 * 	2. This password is then used to (bref, j'ai compris)
 * 	3. If the couple Username/Password matches, then the password is salted
 * 	   using the master_psk_user's salt, and hashed using SHA-256
 * 	
 *
 * Parameters: 
 *	psk_generated_key:	An allocated buffer where the master key will
 *				be stored once generated
 * Return value:
 * 	AUTH_SUCCESS 	if the master key has been generated
 * 	AUTH_DENIED 	if the checking of the password fails three times in a
 * 			a row. The checking fails if : 
 * 				- The given password is wrong 
 * 				- No password could be fetched from the 
 * 				  standard input
 * XXX:
 * 	For the moment, the master_psk_username is a constant. In the future, 
 * 	it could be nice for it be set manually e.g. through a config file
 */
int auth_master_psk(char *out_key)
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

		if(unpwd_client_auth(MASTER_PSK_USERNAME, pwd)) break;
	}

	/* Generate and store the PSK Master Key */
	char salt[SALT_LEN + 1]; 
	db_i.get_salt(MASTER_PSK_USERNAME, salt);

	int err = compute_master_key(pwd, salt, out_key);

	free(pwd);	

	if(err){
		auth_log_error("Could not generate the PSK Master Key");
		return AUTH_FAILURE;
	} else {
		auth_log_info("Successfuly generated the PSK Master Key");
		return AUTH_SUCCESS;
	}
}

/*
 * Function: auth_client 
 *
 * This function checks in that the client that attempts 
 * to connect to the broker is giving valid credentials.
 *
 * It does it in three steps :
 *
 * 	1. It fetches the salt from the database corresponding to the given
 * 	   username
 *
 * 	2. It hashes the given password using Argon2 and the fetched salt 
 *
 * 	3. It checks that the Username/Hash couple corresponds to a single row 
 * 	   in the "credentials" table of the DB
 *
 * Parameters:
 * 	username: 	the username given by the client
 * 	password:	the password given by the client
 *
 * Return Value:
 * 	AUTH_SUCCESS if the client has given some valid credentials 
 *	AUTH_DENIED if the credentials given by the client are not valid
 *	AUTH_FAILURE if the check of the credentials could not be completed
 *
 *
 * FIXME : 
 *
 * 	If the salt cannot be fetched because the DB returned a null row, it
 * 	probably means that the username does not exist in the database and, 
 * 	in this case, the function should return AUTH_DENIED and not 
 * 	AUTH_FAILURE
 */
int auth_client(const char * username, const char * password)
{
	int return_code = 0;
	long long int result;

	char *salt_buf = (char *)malloc(sizeof(char) * (SALT_LEN+1));
	char *hash_buf = (char *)malloc(sizeof(char) * (HASH_LEN+1));

	if(db_i.get_salt(username, salt_buf))
		return_code = AUTH_FAILURE;
	
	else if(hash_password(password, salt_buf, hash_buf))
		return_code = AUTH_FAILURE;

	else if (db_i.pw_check(username, hash_buf, &result))
		return_code = AUTH_FAILURE;

	free(salt_buf);
	free(hash_buf);

	if(return_code) 
		return return_code;
	
	return (result == 1) ? AUTH_SUCCESS : AUTH_DENIED;
}

/*
 * Function: auth_psk_getter 
 *
 * This function retrieves the Pre-Shared-Key stored in the DB and associated 
 * to the identiy provided by the client.
 *
 * It does it in two steps :
 * 	1. It retrieves the cyphered PSK and its salt from the DB
 * 	2. It uncyphers it using the AES256-CBC algorithm
 *
 * Parameters:
 * 	identity: A C-String that contains the identity provided by the client
 * 	psk_key: An allocated buffer where the uncyphered PSK will be stored
 *
 * Return value:
 * 	AUTH_SUCCESS if the PSK has been retrieved and correctly uncyphered
 * 	AUTH_DENIED if the identity was not foud in the DB
 * 	AUTH_FAILURE if the key could not be fetched or uncyphered
 *
 * FIXME: 
 *	At the moment, if the identity does not exists in the DB, the function
 *	returns AUTH_FAILURE, when it should return AUTH_DENIED.
 */
int auth_psk_getter(const char * identity, char * psk_key)
{

	char *init_vector = (char *) malloc(sizeof(char) * IV_LEN); 
	char *cyphered_key = (char *) malloc(sizeof(char) * KEY_LEN);
	
	if(db_i.fetch_psk_key(identity, init_vector, cyphered_key)){ 
		free(cyphered_key);
		free(init_vector);

		return AUTH_FAILURE;
	} 
	
	int decypher_error = decypher_key(psk_master_key, cyphered_key, init_vector, psk_key);
	free(cyphered_key);
	free(init_vector);

	return decypher_error ? AUTH_FAILURE: AUTH_SUCCESS;	
}
