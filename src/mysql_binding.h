#pragma once

#include <mysql/mysql.h>
#include <libconfig.h>

#define MYSQL_DEFAULT_HOST NULL
#define MYSQL_DEFAULT_PORT 0 
#define MYSQL_DEFAULT_AUTH_SOCKET "/run/mysqld/mysqld.sock"

#define MYSQL_DEFAULT_DB_NAME "mosquitto_auth"
#define MYSQL_DEFAULT_CREDS_TAB_NAME "unpwd_client"
#define MYSQL_DEFAULT_PSK_TAB_NAME "psk"
#define MYSQL_DEFAULT_MASTER_PSK_TAB_NAME "master_psk"
#define MYSQL_DEFAULT_ACL_TAB_NAME "acl"

#define NO_PORT 0
#define NO_FLAG 0

#define MAX_STMT_LEN 200

struct mysql_settings{
	MYSQL * handler;

	MYSQL_STMT *stmt_salt;
	MYSQL_STMT *stmt_psk;
	MYSQL_STMT *stmt_auth;

	int port;

	const char *username;
	const char *password;

	const char *host;
	const char *unix_socket;

	const char *db_name;
	const char *creds_tab_name;	
	const char *psk_tab_name;
	const char *acl_group_tab_name;
};

extern const char *mysql_cfg_setting;
extern const char *mysql_string_settings[];
extern const char *mysql_int_setting[];
extern const char *mysql_bool_setting[];

extern const struct DB_settings_layout mysql_set_layout;

/*
 * Function: mysql_cfg_init
 *
 * This function initializes the MySQL Handler. It is called only once, 
 * the first time the plugin is loaded
 *
 * Return value:
 * 	DB_SUCCESS if the handler is correctly initialized
 * 	DB_FAILURE if the handler cannot be initialized
 */
int mysql_cfg_init(struct DB_instance *db_i);

/*
 * Function: mysql_connect
 *
 * This function attempts to connect to the MySQL Database using the
 * previously initialized MYSQL structure.
 *
 * It is called at least once during the plugin's security init.
 *
 * XXX : For the moment, most of the connection parameters are constant,
 * but when the project will work, it could be nice to be able to choose 
 * the connection settings e.g. through the mosquitto config file 
 *
 * Parameters:
 * 	username: The MySQL username of the account used to access the DB
 * 	password: The MySQL pw of that account
 *
 * Return Value: 
 *	DB_SUCCESS if the connection to the DB is successfull
 *	DB_FAILURE if the connection to the DB failed
 *
 */
int mysql_connect();

/*
 * Function : mysql_disconnect
 *
 * This function resets and disconnects the previously established connection.
 * It is called during the plugin's security shutdown phase
 *
 */
void mysql_disconnect(void);

/*
 * Function: mysql_cleanup 
 *
 * This function is called when the plugin is fully stopped and calls the 
 * MySQL API memory cleaners.
 *
 */
void mysql_cleanup(void);

/*
 * Function: mysql_stmt_bind_param
 *
 * This function initializes and sets the different fields of a previously 
 * allocated MYSQL_BIND array, then binds it to an initialized MYSQL_STMT 
 * as its parameters.
 *
 * It is a variadic function and can therefore bind an arbitrary number of 
 * parameters to a prepared statement.
 *
 * Parameters:
 *	stmt: 		Pointer to the start of the MYSQL_STMT to bind 
 *	bnd: 		Pointer to the start of the allocated MYSQL_BIND array
 *	row_count: 	The number of parameters to bind (must be > 0)
 *
 * 	The <row_count> argument determines how many arguments must follow. In
 * 	this case, there must always be 3*row_count arguments after row_count.
 *
 * 	Each groups of three consecutives arguments (after row_count) 
 * 	are associated to one parameter of the prepared statement. If we take 
 * 	the n-th group of three arguments, they correspond to (in this order) :
 *
 * 		1. The MySQL API type of the n-th parameter of the prepared statement
 * 		2. The pointer to the actual value of parameter
 * 		3. The length of the parameter 
 *	
 *	The behaviour of this function if the number of argument is passed does
 *	no correspond to the value of <row_count> is undefined.
 *
 * 	Here is an example of call to this function :
 *	
 *	'''
 *	MYSQL_BIND bnd[2];
 *	int param1 = 4;
 *	char *param2 = "foo";
 *
 * 	mysql_stmt_bind_param(example_stmt, example_bnd, 2,
 * 			MYSQL_TYPE_INTEGER, &param1, sizeof(int),
 * 			MYSQL_TYPE_STRING, param2, strlen(param2)); 
 *	'''
 */
void _mysql_stmt_bind_param(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, ...);

/*
 * Function: mysql_stmt_bind_result
 *
 * This function initializes and sets the different fields of a previously 
 * allocated MYSQL_BIND array, then binds it to an initialized MYSQL_STMT 
 * as its result rows.
 *
 * It is a variadic function and can therefore bind an arbitrary number of 
 * result rows to a prepared statement.
 *
 * Parameters:
 *	stmt: 		Pointer to the start of the MYSQL_STMT to bind 
 *	bnd: 		Pointer to the start of the allocated MYSQL_BIND array
 *	row_count: 	The number of results row to bind (must be > 0)
 *
 * 	The <row_count> argument determines how many arguments must follow. In
 * 	this case, there must always be 6*row_count arguments after row_count.
 *
 * 	Each groups of six consecutives arguments (after row_count) 
 * 	are associated to one result row of the prepared statement. If we take 
 * 	the n-th group of six arguments, they correspond to (in this order) :
 *
 * 		1. The MySQL API type of the n-th result column 
 * 		2. A pointer to a buffer where the value of the row should be 
 * 		   stored
 * 		3. The size of the buffer   
 * 		4. A pointer to an integer where the value of byte written in
 * 		   the buffer should be stored
 * 		5. A pointer to an integer that will be set to 1 if the value
 * 		   in the column has been truncated when fetched (happens when 
 * 		   the buffer is not long enough to contain the value of the 
 * 		   column) 
 * 		6. A pointer to a mysql_bool that will be set to 1 if the 
 * 		   column contains an empty value
 *	
 *	The behaviour of this function if the number of argument is passed does
 *	no correspond to the value of <row_count> is undefined.
 *
 * 	Here is an example of call to this function :
 *	
 *	'''
 *	MYSQL_BIND bnd[2];
 *	int param1 = 4;
 *	char *param2 = "foo";
 *
 * 	mysql_stmt_bind_param(example_stmt, example_bnd, 2,
 * 			MYSQL_TYPE_INTEGER, &param1, sizeof(int),
 * 			MYSQL_TYPE_STRING, param2, strlen(param2)); 
 *	'''
 */
void _mysql_stmt_bind_result(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, ...);

/*
 * Function: mysql_prepare_statements
 *
 * This function initilizes and set the different prepared statements 
 * used by the plugin
 *
 * Parameters:
 * 	sql_handler: 	The handler of the previously connected MySQL DB
 *
 */
void mysql_prepare_statements(void);

/*
 * Function: mysql_close_statements
 *
 * This function will close all previously prepared statements, and is called 
 * whenever the plugin is being reloaded or stopped. 
 *
 */ 
void mysql_close_statements(void);

/*
 * Function: mysql_pw_check
 *
 * This function will execute the <stmt_auth> prepared statement with the 
 * "username" and "hash_buff" argument as parameters, so that the following
 * SQL statement is executed :
 *
 * < SELECT COUNT(*) FROM credentials WHERE username="username" AND
 * password_hash ="hash_buff" >
 *
 *
 * Parameters:
 * 	username: The username given by the incoming client 
 *	hash_buff: The hash of the password given by the client 
 *	p_result: Pointer to the int that will store the result of the Query 
 *
 * Return value:
 *	DB_SUCCESS if the query executed properly, and the result could be retrieved
 *	DB_FAILURE if an error occured
 *
 */
int mysql_pw_check(const char *username, const char *hash_buff, 
		long long int *p_result);

/*
 * Function: mysql_get_salt
 *
 * This function fetches the salt associated to the given username from the 
 * MySQL DB.
 *
 * Parameters:
 * 	username: 	pointer to the C-string containing the username
 * 	salt_buf: 	pointer to an allocated buffer that will contain the 
 * 			fetched salt on success
 *
 * Return Value:
 * 	DB_SUCCESS on success 
 * 	DB_FAILURE if an error occured or if the given username does not exist 
 */
int mysql_get_salt(const char *username, char *salt_buf);

/*
 * Function: mysql_fetch_psk_key
 *
 * This function fetches the Initit Vector and the Cyphered Key associated
 * to a given identity. It executes the <stmt_psk> prepared statement such
 * that the resulting SQL query is :
 *
 * SELECT cyphered_PSK,init_vector FROM psk Where identity="identity" 
 *
 * Parameters:
 * 	identity: 	A C-string containing the identity from which we want
 * 			to obtain the IV an the cyphered key 
 * 	iv:		An allocated buffer which will contain the fetched Init
 * 			Vector	
 * 	key:		An allocated buffer which will contain the fetched 
 * 			Cyphered key 	
 *
 * Return value:
 * 	DB_SUCCESS on success
 * 	DB_FAILURE on failure
 *
 */
int mysql_fetch_psk_key(const char *identity, char *iv, char *key);
