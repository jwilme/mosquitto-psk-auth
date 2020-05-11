#include <termios.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>

#include "mysql.h"
#include "crypto.h"
#include "auth.h"

#define LOG_AUTH_ERROR_PREFIX 		"[AUTH - ERROR] ::"
#define LOG_AUTH_WARNING_PREFIX 	"[AUTH - WARNING] ::"
#define LOG_AUTH_INFO_PREFIX 		"[AUTH - INFO] ::"

#define auth_log_error(char * fmt, ...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_AUTH_ERROR_PREFIX, char *fmt, ...)

#define auth_log_warning(char * fmt, ...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_AUTH_WARNING_PREFIX, char *fmt, ...)

#define auth_log_info(char * fmt, ...) \
	plugin_log(MOSQ_LOG_INFO, LOG_AUTH_INFO_PREFIX, char *fmt, ...)

/*
 * Function: db_connection
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
int db_connection()
{
	/* Prompt for Password and Attempt to Connect to the DB */
	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			auth_log_error("Max number of MySQL Authentication "
					"attempts reached");
			return AUTH_DENIED;
		}

//XXX : Password is not allocated by getline, a malloc has to be done, but I 
//	need to avoid to realloc it at every attempt
		printf("Password : ")
		if(prompt_password(&password) < 0){
			auth_log_error("Unable to prompt for the password");	
			continue;
		} 
		
		else if(mysql_connect(username, (const char *)password)){
			free(password);		
		}
	       
		else{
			break;
		}
	}

	free(db_password);
	return AUTH_SUCCESS;
}

/*
 * Function: psk_init
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
int psk_init(char *psk_generated_key)
{
	/* Prompt for Password and Check that it is the correct key */
	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			auth_log_error("Max number of PSK Authentication "
					"attempts reached");
			return AUTH_DENIED;
		}
		//
//XXX : Password is not allocated by getline, a malloc has to be done, but I 
//	need to avoid to realloc it at every attempt
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

/*
 * Function: unpwd_client_auth
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

/*
 * Function: psk_client_auth
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
