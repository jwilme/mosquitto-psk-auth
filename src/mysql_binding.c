#include <mysql/mysql.h>

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>

#include "auth.h"
#include "plugin_log.h"

#include "mysql_binding.h"

#define LOG_MYSQL_ERROR 	"[MYSQL - ERROR] ::"
#define LOG_MYSQL_WARNING 	"[MYSQL - WARNING] ::"
#define LOG_MYSQL_INFO 		"[MYSQL - INFO] ::"

#define mysql_log_error(char * fmt, ...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_MYSQL_ERROR, char *fmt, ...)

#define mysql_log_warning(char * fmt, ...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_MYSQL_WARNING, char *fmt, ...)

#define mysql_log_info(char * fmt, ...) \
	plugin_log(MOSQ_LOG_INFO, LOG_MYSQL_INFO, char *fmt, ...)

MYSQL * db_handler;

MYSQL_STMT * stmt_salt;
MYSQL_STMT * stmt_psk;
MYSQL_STMT * stmt_auth;

/*
 * Function: mysql_init
 *
 * This function initializes the MySQL Handler. It is called only once, 
 * the first time the plugin is loaded
 *
 * Return value:
 * 	DB_SUCCESS if the handler is correctly initialized
 * 	DB_FAILURE if the handler cannot be initialized
 */
int mysql_init()
{
	MYSQL * db_handler = mysql_init(NULL);

	if(!db_handler){
		mysql_log_error("Could not initialize the database handler");
		return DB_FAILURE;
	}

	return DB_SUCCESS;
}

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
int mysql_connect(const char *username, const char *password);
{
	int err = mysql_real_connect(user_data, LOCALHOST, username, password, DB_NAME, NO_PORT,
		       DB_UNIX_SOCKET, NO_FLAG);
	if(err){
		mysql_log_error("DB returned an error on connection : %s",
			       mysql_errno(db_handler));	
		return DB_FAILURE;
	}else{
		mysql_log_info("Successfully log in the DB as %s", username);
		return DB_SUCCESS;
	}
}

/*
 * Function : mysql_disconnect
 *
 * This function resets and disconnects the previously established connection.
 * It is called during the plugin's security shutdown phase
 *
 */
void mysql_disconnect()
{
	mysql_log_info("Disconnecting from the database");
	mysql_reset_connection((MQTT *)db_handler);
	mysql_close((MQTT *)db_handler);
}

/*
 * Function: mysql_cleanup 
 *
 * This function is called when the plugin is fully stopped and calls the 
 * MySQL API memory cleaners.
 *
 */
void mysql_cleanup()
{
	mysql_log_info("Ending MySQL Library");
	mysql_library_end();
}

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
void mysql_stmt_bind_param(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, ...)
{
	memset(bnd, 0, sizeof(MYSQL_BIND)*row_count);

	va_list va;
	va_start(va, row_count);

	for(int i = 0; i < row_count; i++){
		bnd[i].buffer_type = va_arg(va, int);  	
		bnd[i].buffer = va_arg(va, void *); 
		bnd[i].buffer_length = va_arg(va, int);
	}
	
	va_end(va);
	mysql_stmt_bind_param(stmt, bnd); 
}

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
void mysql_stmt_bind_result(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, ...)
{
	memset(bnd, 0, sizeof(MYSQL_BIND)*row_count);

	va_list va;
	va_start(va, row_count);

	for(int i = 0; i < row_count; i++){
		bnd[i].buffer_type = va_arg(va, int);  	
		bnd[i].buffer = va_arg(va, void *);	
		bnd[i].buffer_length = va_arg(va, long); 	

		void *len = va_arg(va, void *);
		void *err = va_arg(va, void *);
		void *in = va_arg(in, void *);

		if(len) bnd[i].length = len;	
		if(err) bnd[i].error = err;  	
		if(in) 	bnd[i].is_null = in;
	}

	va_end(va);
	mysql_stmt_bind_result(stmt, bnd); 
}

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
void mysql_prepare_statements(MYSQL * sql_handler)
{
	/* Prepare the Salt statement */
	stmt_salt = mysql_stmt_init(sql_handler); 
	stmt_salt = mysql_stmt_prepare(stmt_salt, 
			SALT_QUERY, 
			strlen(SALT_QUERY)
			);

	/* Prepare the PSK statement */
	stmt_psk = mysql_stmt_init(sql_handler); 
	stmt_psk = mysql_stmt_prepare(stmt_psk, 
			PSK_CLIENT_QUERY, 
			strlen(PSK_CLIENT_QUERY)
			);

	/* Prepare the Authentication statement */
	stmt_auth = mysql_stmt_init(sql_handler); 
	stmt_auth = mysql_stmt_prepare(stmtauth, 
			UNPWD_CLIENT_QUERY, 
			strlen(UNPWD_CLIENT_QUERY)
			);
}

/*
 * Function: mysql_close_statements
 *
 * This function will close all previously prepared statements, and is called 
 * whenever the plugin is being reloaded or stopped. 
 *
 */ 
void mysql_close_statements()
{
	mysql_log_info("Closing all statements");

	mysql_stmt_close(stmt_salt);
	mysql_stmt_close(stmt_psk);
	mysql_stmt_close(stmt_auth);
}


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
int mysql_pw_check(const char *username, const char *hash_buff, int *p_result)
{
	MYSQL_BIND auth_query_bind[1];
	MYSQL_BIND auth_result_bind[1];

	mysql_bool auth_is_null;

	stmt_bind_param(stmt_auth, auth_query_bind, 1,
		MYSQL_TYPE_BINARY, hash_buf, HASH_LEN+1);

	stmt_bind_result(stmt_auth, auth_result_bind, 1,
		MYSQL_TYPE_LONGLONG, p_result, NULL, NULL, &is_null); 

	mysql_stmt_execute(stmt_auth);

	switch(mysql_stmt_fetch(stmt_auth)){
	case(0):
		if(!auth_is_null)
			return DB_SUCCESS;

		mysql_log_error("(Username : %s) The Hash count query "
				"returned a null row",
				username);
		return DB_FAILURE;

	case(1):
		mysql_log_error("(Username : %s) Result Fetch Error : %s \n", 
				username, 
				mysql_stmt_errno(stmt_auth);

	default:
		return DB_FAILURE; 

	}
}

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
int mysql_get_salt(const char *username, char *salt_buf)
{
	MYSQL_BIND salt_query_bind[1], salt_result_bind[1];
	long salt_len; 

	stmt_bind_param(stmt_salt, salt_query_bind, 1,
			MYSQL_TYPE_STRING, username, strlen(username)); 

	stmt_bind_result(stmt_salt, salt_result_bind, 1, 
		MYSQL_TYPE_BINARY, salt_buf, SALT_LEN, salt_len, NULL, NULL);

	mysql_stmt_execute(stmt_salt);	
	int err = mysql_stmt_fetch(stmt_salt);
	
	if(!err){	
		if(salt_len != SALT_LEN){
			mysql_log_error("(Username : %s) The fetched salt is "
					"not of the expected size :: "
					"Fetched : %d || Expected : %d",
					username, salt_len, SALT_LEN);

			return DB_FAILURE;
		}
		return DB_SUCCESS;	
	
	} 
	
	else if(err == 1){
		mysql_log_error("(Username : %s) : Result Fetch Error : %s \n", 
				username, mysql_stmt_errno(stmt_salt));	
	} 
	
	else if(err == MYSQL_DATA_TRUNCATED){
		mysql_log_error("(Username : %s) : The Salt has been truncated "
			       	"when fetched\n", 
				username);
	} 
	
	else if(err == MYSQL_NO_DATA){
		mysql_log_error("(Username : %s) : There is no row associated "
				"to the given username");
	}

	return DB_FAILURE;
}

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
int mysql_fetch_psk_key(const char * identity, char * iv, char * key)
{
	MYSQL_BIND psk_query_bind[1], psk_result_bind[2];
	int length[2], error[2];

	stmt_bind_param(stmt_psk, psk_query_bind, 1,
		MYSQL_TYPE_STRING, identity, strlen(identity));

	stmt_bind_result(stmt_psk, psk_result_bind, 2,
		MYSQL_TYPE_BINARY, init_vector, IV_LEN, length, error, NULL,
		MYSQL_TYPE_BINARY, cyphered_key, KEY_LEN, length+1, error+1, NULL
		);

	mysql_stmt_execute(stmt_psk);	
	int err = mysql_stmt_fetch(stmt_psk);

	if(!err){
		if(length[0] != KEY_LEN || length[1] != SALT_LEN){
			mysql_log_error("(Identity %s) : PSK key and/or IV are "
					"not the right size", identity);
			return DB_FAILURE;
		}
		return DB_SUCCESS;		 
	}

	else if(err == 1){
		mysql_log_error("(Identity %s) : Error when fetching result :"
			       " %s", identity, mysql_stmt_errno(stmt_psk)); 
	}

	else if(err == MYSQL_DATA_TRUNCATED){
		mysql_log_error("(Identity : %s) PSK key or IV truncated",
				identity);
	}

	else if(err == MYSQL_NO_DATA){
		mysql_log_error("(Identity : %s) No Identity in the database"
				"matches the given one");
	}

	return DB_FAILURE;	
}	
