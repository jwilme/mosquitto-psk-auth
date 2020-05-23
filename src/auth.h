#pragma once

enum Auth_ErrorCodes {
	AUTH_SUCCESS = 0,
	AUTH_DENIED = 1,
	AUTH_FAILURE = 2,
};

#define MAX_CREDENTIAL_SIZE 40
#define RETRY_LIMITS 3

/*
 * Function: auth_init
 *
 * This function receives the initialized DB_instance for the session that
 * will allow it to call the different back_end functions when needed. 
 *
 * Parameters:
 *	db_inst : 	a pointer to an initialized DB_instance structure 
 *
 * Return Value:
 *	AUTH_SUCCESS
 *	
 */
int auth_init(struct DB_instance *db_inst);

/*
 * Function: auth_connect_db 
 *
 * This function attempts to connect to the database. It is called only
 * when the plugin is started or reloaded
 *
 * Return value:
 * 	AUTH_SUCCESS if a connection has been established with the DB
 * 	AUTH_DENIED if not
 */
int auth_connect_db(void);

/*
 * Function: auth_master_psk 
 *
 * This function will generate the psk_master_key used to decypher the
 * clients' PSK stored in the DB. 
 *
 * XXX : At the moment, it is not decided how this should be done. Therefore,
 * this function has no effect and, unless the psk_plugin function is 
 * implemented, is never call.
 *
 * Return value:
 * 	AUTH_SUCCESS all the time	
 */
int auth_master_psk(void);

/*
 * Function: auth_client 
 *
 * This function checks that the client that attempts 
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
 * TODO:
 * 	It could be interesting to be able to set the parameter of Argon2 on a
 * 	per-client basis, depending for example, on the level of privileges a 
 * 	client has.
 *
 * 	It could also be interesting to be able to chose which hash algorithm 
 * 	is used on a per-client basis as well. 
 */
int auth_client(const char *username, const char *password);

/*
 * Function: auth_get_psk 
 *
 * This function retrieves the Pre-Shared-Key stored in the DB and associated 
 * to the identiy provided by the client.
 *
 * XXX : This function at the moment does not nothing, and is never called
 * unless the psk plugin function is implemented, in which case, this 
 * function directly returns AUTH_FAILURE
 *
 * Parameters:
 * 	identity: A C-String that contains the identity provided by the client
 * 	psk_key: An allocated buffer where the uncyphered PSK will be stored
 *
 * Return value:
 * 	AUTH_FAILURE if the key could not be fetched or uncyphered
 *
 */
int auth_get_psk(const char *identity, char *psk_key);

/*
 * Function: auth_disconnect
 * 
 * This function disconnects the database, and frees all the structures
 * and buffer that are not usefull anymore.
 *
 * Return value:
 *	AUTH_SUCCESS all the time
 *
 */
int auth_disconnect(void);

/*
 * Function: auth_cleanup
 *
 * This function performs the cleanup of the DB structure when the plugin is 
 * about to be ended.
 *
 * Return value:
 *	AUTH_SUCCESS all the time
 */
int auth_cleanup(void);
