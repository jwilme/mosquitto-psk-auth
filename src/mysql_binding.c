#include <mysql/mysql.h>

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include "db_common.h"
#include "crypto.h"
#include "mysql_binding.h"
#include "plugin_log.h"

#define LOG_MYSQL_ERROR 	"[MYSQL - ERROR] ::"
#define LOG_MYSQL_WARNING 	"[MYSQL - WARNING] ::"
#define LOG_MYSQL_INFO 		"[MYSQL - INFO] ::"


#define mysql_log_error(...) \
	plugin_log(LOG_MYSQL_ERROR, __VA_ARGS__)

#define mysql_log_warning(...) \
	plugin_log(LOG_MYSQL_WARNING, __VA_ARGS__)

#define mysql_log_info(...) \
	plugin_log(LOG_MYSQL_INFO, __VA_ARGS__)


MYSQL * mysql_handler;

MYSQL_STMT * stmt_salt;
MYSQL_STMT * stmt_psk;
MYSQL_STMT * stmt_auth;

int mysql_db_init()
{
	mysql_handler = mysql_init(NULL);

	if(!mysql_handler){
		mysql_log_error("Could not initialize the database handler");
		return DB_FAILURE;
	}

	return DB_SUCCESS;
}

int mysql_connect(const char *username, const char *password)
{
	MYSQL * handler = mysql_real_connect(mysql_handler, LOCALHOST, username, 
			password, DB_NAME, NO_PORT, DB_UNIX_SOCKET, NO_FLAG);
	if(!handler){
		mysql_log_error("DB returned an error on connection : %s",
			       mysql_errno(mysql_handler));	
		return DB_FAILURE;
	}else{
		mysql_log_info("Successfully log in the DB as %s", username);
		return DB_SUCCESS;
	}
}

void mysql_disconnect()
{
	mysql_log_info("Disconnecting from the database");
	mysql_reset_connection(mysql_handler);
	mysql_close(mysql_handler);
}

void mysql_cleanup()
{
	mysql_log_info("Ending MySQL Library");
	mysql_library_end();
}

void _mysql_stmt_bind_param(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, 
		...)
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

void _mysql_stmt_bind_result(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, 
		...)
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
		void *in = va_arg(va, void *);

		if(len) bnd[i].length = len;	
		if(err) bnd[i].error = err;  	
		if(in) 	bnd[i].is_null = in;
	}

	va_end(va);
	mysql_stmt_bind_result(stmt, bnd); 
}

void mysql_prepare_statements()
{
	/* Prepare the Salt statement */
	stmt_salt = mysql_stmt_init(mysql_handler); 
	(void)mysql_stmt_prepare(stmt_salt, SALT_QUERY, strlen(SALT_QUERY));

	/* Prepare the PSK statement */
	stmt_psk = mysql_stmt_init(mysql_handler); 
	(void)mysql_stmt_prepare(stmt_psk, PSK_CLIENT_QUERY, 
			strlen(PSK_CLIENT_QUERY));

	/* Prepare the Authentication statement */
	stmt_auth = mysql_stmt_init(mysql_handler); 
	(void)mysql_stmt_prepare(stmt_auth, UNPWD_CLIENT_QUERY, 
			strlen(UNPWD_CLIENT_QUERY));
}

void mysql_close_statements()
{
	mysql_log_info("Closing all statements");

	mysql_stmt_close(stmt_salt);
	mysql_stmt_close(stmt_psk);
	mysql_stmt_close(stmt_auth);
}


int mysql_pw_check(const char *username, const char *hash_buff, 
		long long int *p_result)
{
	MYSQL_BIND auth_query_bind[1];
	MYSQL_BIND auth_result_bind[1];

	my_bool auth_is_null;

	_mysql_stmt_bind_param(stmt_auth, auth_query_bind, 1,
		MYSQL_TYPE_BLOB, hash_buff, HASH_LEN+1);

	_mysql_stmt_bind_result(stmt_auth, auth_result_bind, 1,
		MYSQL_TYPE_LONGLONG, p_result, NULL, NULL, &auth_is_null); 

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
		mysql_log_error("(Username : %s) Result Fetch Error : %s", 
				username, 
				mysql_stmt_errno(stmt_auth));
		return DB_FAILURE; 

	default:
		return DB_FAILURE;
	}
}

int mysql_get_salt(const char *username, char *salt_buf)
{
	MYSQL_BIND salt_query_bind[1], salt_result_bind[1];
	long salt_len; 

	_mysql_stmt_bind_param(stmt_salt, salt_query_bind, 1,
			MYSQL_TYPE_STRING, username, strlen(username)); 

	_mysql_stmt_bind_result(stmt_salt, salt_result_bind, 1, 
		MYSQL_TYPE_BLOB, salt_buf, SALT_LEN, &salt_len, NULL, NULL);

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

int mysql_fetch_psk_key(const char * identity, char * iv, char * key)
{
	MYSQL_BIND psk_query_bind[1], psk_result_bind[2];
	int length[2], error[2];

	_mysql_stmt_bind_param(stmt_psk, psk_query_bind, 1,
		MYSQL_TYPE_STRING, identity, strlen(identity));

	_mysql_stmt_bind_result(stmt_psk, psk_result_bind, 2,
		MYSQL_TYPE_BLOB, iv, IV_LEN, length, error, NULL,
		MYSQL_TYPE_BLOB, key, KEY_LEN, length+1, error+1, NULL
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
