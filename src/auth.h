#pragma once

enum Auth_ErrorCodes {
	AUTH_SUCCESS = 0,
	AUTH_DENIED = 1,
	AUTH_FAILURE = 2,
};

#define MASTER_PSK_USERNAME "master_psk"
#define MAX_CREDENTIAL_SIZE 40
#define RETRY_LIMITS 3

typedef int 	(*DB_init)(void);
typedef int 	(*DB_connect)(const char *, const char *);
typedef void 	(*DB_disconnect)(void);
typedef void 	(*DB_cleanup)(void);
typedef void 	(*DB_prepare_statements)(void);
typedef void 	(*DB_close_statements)(void);
typedef int 	(*DB_pw_check)(const char *, const char *, long long int *);
typedef int 	(*DB_get_salt)(const char *, char *); 
typedef int 	(*DB_fetch_psk_key)(const char *, char *, char *);

struct DB_instance{
	DB_init init;
	DB_connect connect;
	DB_disconnect disconnect;
	DB_cleanup cleanup;
	DB_prepare_statements prepare_statements; 
	DB_close_statements close_statements;
	DB_pw_check pw_check; 
	DB_get_salt get_salt; 
	DB_fetch_psk_key fetch_psk_key;
};

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
int auth_init(struct mosquitto_opt * opts, int opt_count);

/*
 * Function: auth_connect_db 
 *
 * This functions prompts for a password in the standard input, and will 
 * attempt to connect to the DB using the given credentials.
 *
 * For the moment, the username to connect to the database is fetched from
 * the plugin configuration file.
 *
 * Return value:
 * 	AUTH_SUCCESS if the connection is established to the database
 * 	AUTH_DENIED if the connection attemp fails "RETRY_LIMITS" times
 */
int auth_connect_db(void);

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
int auth_master_psk(char *psk_generated_key);

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
 * 	If the salt cannot be fetched because the DB returned a null row, it
 * 	probably means that the username does not exist in the database and, 
 * 	in this case, the function should return AUTH_DENIED and not 
 * 	AUTH_FAILURE
 */
int auth_client(const char *username, const char *password);

/*
 * Function: auth_get_psk 
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
int auth_get_psk(const char *identity, char *psk_key);
