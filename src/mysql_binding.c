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

int mysql_init(void **user_data)
{
	MYSQL * db_handler = mysql_init(NULL);

	if(!db_handler){
		mysql_log_error("Could not initialize the database handler");
		return DB_FAILURE;
	}
	psk_key = (char *)calloc(sizeof(char) * (KEY_LEN + 1));	

	return DB_SUCCESS;
}

void mysql_startup(void * user_data);
{
	//Authenticate to the database
	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			mysql_log_error("Max number of MySQL Authentication "
					"attempts reached");
			return DB_FAILURE;
		}
	
		char * db_password;	
		// PROMPT FOR PASSWORD

		int err = mysql_real_connect( (MYSQL *)user_data, NULL, 
				"mqtt_broker", db_password, "test", 0, 
				"/run/mysqld/mysqld.sock", 0); 

		if(!err){
			mysql_log_info("Successfuly connected to the Database");
			break;
		} 
		
		else{
			mysql_log_warning("Unable to connect to the DB : %s",
					mysql_errno((MYSQL *)user_data);
		}
	}
	
	prepare_statements((MYSQL *)user_data);

	//Give the password of the stored PSK-keys 
	for(int i = 0; i < RETRY_LIMITS; i++){
		char * psk_password;	
		// PROMPT FOR PASSWORD	

		if(!psk_master_auth(psk_password, psk_key)){ 	
			return DB_SUCCESS;		
		}

		else if{

		}

		else{

		}
	}

	mysql_log_error("Max attempt of psk authentication reached");
	return DB_FAILURE;
}

void mysql_shutdown(void *user_data)
{
	mysql_log_info("Disconnecting from the database");
	mysql_reset_connection((MQTT *)user_data);
	mysql_close((MQTT *)user_data);

	return ACCESS_GRANTED;
}

void mysql_cleanup()
{
	mysql_log_info("Ending MySQL Library");
	mysql_library_end();
	return ACCESS_GRANTED;
}

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


void mysql_close_statements()
{
	/* Close all previously prepared statements */
	mysql_log_info("Closing all statements");
	mysql_stmt_close(stmt_salt);
	mysql_stmt_close(stmt_psk);
	mysql_stmt_close(stmt_auth);
}

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
		if(auth_is_null){
			mysql_log_error("(Username : %s) The Hash count query "
					"returned a null row",
					username);

			return ACCESS_FAILURE;
		}
		break;

	case(1):
		char * err = mysql_stmt_errno(stmt_auth);
		mysql_log_error("(Username : %s) Result Fetch Error : %s \n", 
				username, 
				err);

		return ACCESS_FAILURE;
	
	default:
		return ACCESS_DENIED; 

	}
}

int mysql_get_salt(const char *username, char *salt_buf)
{
	MYSQL_BIND salt_query_bind[1], salt_result_bind[1];
	long salt_len; 

	stmt_bind_param(stmt_salt, salt_query_bind, 1,
			MYSQL_TYPE_STRING, username, strlen(username)); 

	stmt_bind_result(stmt_salt, salt_result_bind, 1, 
		MYSQL_TYPE_BINARY, salt_buf, SALT_LEN, salt_len, NULL, NULL);

	mysql_stmt_execute(stmt_salt);	

	switch(mysql_stmt_fetch(stmt_salt)){
	case(0):
		if(salt_len != SALT_LEN){
			mysql_log_error("(Username : %s) The fetched salt is "
					"not of the expected size :: "
					"Fetched : %d || Expected : %d",
					username,
					salt_len,
					SALT_LEN);

			return ACCESS_FAILURE;
		}
		break;

	case(1):
		char * err = mysql_stmt_errno(stmt_salt);
		mysql_log_error("(Username : %s) : Result Fetch Error : %s \n", 
				username, 
				err);

		return ACCESS_FAILURE;
	
	case(MYSQL_DATA_TRUNCATED):
		mysql_log_error("(Username : %s) : The Salt has been truncated "
			       	"when fetched\n", 
				username);

		return ACCESS_FAILURE;

	case(MYSQL_NO_DATA):
		return ACCESS_DENIED;

	}
}

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

	/* Fetching the current row */  
	switch(mysql_stmt_fetch(stmt_psk)){
	case(0):
		if(length[0] != KEY_LEN || length[1] != SALT_LEN){
			mysql_log_error("(Identity %s) : PSK key and/or IV are "
				       "not the right size", identity);
			return ACCESS_FAILURE;
		}
		break;		 

	case(1):
		char * err = mysql_stmt_errno(stmt_psk);
		mysql_log_error("(Identity %s) : Error when fetching result :"
			       " %s", identity, err); 
		return ACCESS_FAILURE;

	case(MYSQL_DATA_TRUNCATED):
		mysql_log_error("(Identity : %s) PSK key or IV truncated");
		return ACCESS_FAILURE;

	case(MYSQL_NO_DATA):
		return ACCESS_DENIED;
	
	default:
		return ACCESS_DENIED;

	}
}	
