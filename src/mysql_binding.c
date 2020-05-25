#include <mysql/mysql.h>

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include <libconfig.h>

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

char *str_salt, *str_psk, *str_unpwd;
struct mysql_settings set;
const char *mysql_cfg_setting = "mysql_settings";

#define STR_CNT 8
#define INT_CNT 1
#define BOOL_CNT 0

const char *mysql_string_settings[] = {"db_username", "db_password", "db_host",
	"db_unix_socket", "db_name", "credentials_table_name", "psk_table_name",
	"acl_group_table_name"};

const char *mysql_int_setting[] = {"db_port"};	



const struct Settings_layout mysql_set_layout = {
	.str_setting_cnt = STR_CNT,
	.int_setting_cnt = INT_CNT,
	.bool_setting_cnt = BOOL_CNT,
	.str_first = &(set.username),
	.int_first = &(set.port),
	.bool_first = NULL,
	.str_settings = mysql_string_settings,
	.int_settings = mysql_int_setting,
	.bool_settings = NULL 
};	

int mysql_cfg_init(struct DB_instance *db_i)
{
	//Set Default Value for the mysql_settings structure
	set.handler = mysql_init(NULL);

	set.username = "root";
	set.password = "toor";
	set.host = MYSQL_DEFAULT_HOST;	
	set.port = MYSQL_DEFAULT_PORT;
	set.unix_socket = MYSQL_DEFAULT_AUTH_SOCKET;
	set.db_name = MYSQL_DEFAULT_DB_NAME;
	set.creds_tab_name = MYSQL_DEFAULT_CREDS_TAB_NAME;
#ifdef TLS_PSK
	set.psk_tab_name = MYSQL_DEFAULT_PSK_TAB_NAME;
#endif
	set.acl_group_tab_name = MYSQL_DEFAULT_ACL_TAB_NAME;

	//Set the Function of the DB_instance
	db_i->connect = mysql_connect;
	db_i->disconnect = mysql_disconnect;
	db_i->cleanup = mysql_cleanup;
	db_i->pw_check = mysql_pw_check;
	db_i->get_salt = mysql_get_salt;
#ifdef TLS_PSK
	db_i->fetch_psk_key = mysql_fetch_psk_key;
#endif

	return DB_SUCCESS;
}

int mysql_connect()
{
	MYSQL * handler = mysql_real_connect(set.handler, 
			set.host, set.username, set.password, set.db_name,
			set.port, set.unix_socket, 0);
	
	if(!handler){
		mysql_log_error("%s", mysql_error(set.handler));	
		return DB_FAILURE;
	}else{
		mysql_log_info("Successfully log in the DB as %s", set.username);
		mysql_prepare_statements();
		return DB_SUCCESS;
	}
}

void mysql_disconnect()
{
	mysql_log_info("Disconnecting from the database");
	mysql_close_statements();
	mysql_reset_connection(set.handler);
	mysql_close(set.handler);
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

void _mysql_stmt_bind_result(MYSQL_STMT *stmt, MYSQL_BIND *bnd, 
		int row_count, ...)
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
	str_salt = (char *)malloc(sizeof(char) * MAX_STMT_LEN);
	snprintf(str_salt, MAX_STMT_LEN, SALT_QUERY, set.creds_tab_name); 
	set.stmt_salt = mysql_stmt_init(set.handler); 
	(void)mysql_stmt_prepare(set.stmt_salt, str_salt, strlen(str_salt));

#ifdef TLS_PSK
	str_psk = (char *)malloc(sizeof(char) * MAX_STMT_LEN);
	snprintf(str_psk, MAX_STMT_LEN, PSK_QUERY, set.psk_tab_name); 
	set.stmt_psk = mysql_stmt_init(set.handler); 
	(void)mysql_stmt_prepare(set.stmt_psk, str_psk, strlen(str_psk));
#endif

	str_unpwd = (char *)malloc(sizeof(char) * MAX_STMT_LEN);
	snprintf(str_unpwd, MAX_STMT_LEN, UNPWD_QUERY, set.creds_tab_name); 
	set.stmt_auth = mysql_stmt_init(set.handler); 
	mysql_stmt_prepare(set.stmt_auth, str_unpwd, strlen(str_unpwd));
	mysql_log_info("There are %d parameters for the request\n", 
			mysql_stmt_param_count(set.stmt_auth));
}


void mysql_close_statements()
{
	mysql_log_info("Closing all statements");

	free(str_salt);
#ifdef TLS_PSK
	free(str_psk);
#endif 
	free(str_unpwd);

	mysql_stmt_close(set.stmt_salt);
	mysql_stmt_close(set.stmt_psk);
	mysql_stmt_close(set.stmt_auth);
}


int mysql_pw_check(const char *username, const char *hash_buff, 
		long long int *p_result)
{
	MYSQL_BIND auth_query_bind[2], auth_result_bind[1];
	my_bool auth_is_null;

	_mysql_stmt_bind_param(set.stmt_auth, auth_query_bind, 2,
		MYSQL_TYPE_STRING, username, strlen(username),
		MYSQL_TYPE_BLOB, hash_buff, (2*HASH_LEN));

	if(mysql_stmt_execute(set.stmt_auth)){
		mysql_log_error("(Username : %s) Error on exec : %s", username, 
				mysql_stmt_error(set.stmt_auth));
		return DB_FAILURE;
	}

	_mysql_stmt_bind_result(set.stmt_auth, auth_result_bind, 1,
		MYSQL_TYPE_LONGLONG, p_result, NULL, NULL, &auth_is_null); 

	mysql_stmt_store_result(set.stmt_auth);
	switch(mysql_stmt_fetch(set.stmt_auth)){
	case(0):
		if(!auth_is_null)
			return DB_SUCCESS;

		mysql_log_error("(Username : %s) The Hash count query "
				"returned a null row",
				username);
		return DB_FAILURE;

	case(1):
		mysql_log_error("(Username : %s) %s", 
				username, 
				mysql_stmt_error(set.stmt_auth));
		return DB_FAILURE; 

	default:
		return DB_FAILURE;
	}
}

int mysql_get_salt(const char *username, char *salt_buf)
{
	MYSQL_BIND salt_query_bind[1], salt_result_bind[1];
	long salt_len; 

	_mysql_stmt_bind_param(set.stmt_salt, salt_query_bind, 1,
			MYSQL_TYPE_STRING, username, strlen(username)); 

	mysql_stmt_execute(set.stmt_salt);	

	_mysql_stmt_bind_result(set.stmt_salt, salt_result_bind, 1, 
		MYSQL_TYPE_BLOB, salt_buf, (sizeof(char)*(SALT_LEN+1)),
		&salt_len, NULL, NULL);

	mysql_stmt_store_result(set.stmt_salt);
	int err = mysql_stmt_fetch(set.stmt_salt);
	
	if(!err){	
		if(salt_len != SALT_LEN){
			mysql_log_error("(Username : %s) The fetched salt is "
					"not of the expected size :: "
					"Fetched : %d || Expected : %d",
					username, salt_len, SALT_LEN);

			return DB_FAILURE;
		}
		mysql_log_info("Successfully fetched a salt from the DB");
		return DB_SUCCESS;	
	} 
	
	else if(err == 1){
		mysql_log_error("(Username : %s) : Result Fetch Error : %s", 
				username, mysql_stmt_error(set.stmt_salt));	
	} 
	
	else if(err == MYSQL_DATA_TRUNCATED){
		mysql_log_error("(Username : %s) : The Salt has been truncated "
			       	"when fetched. Fetched Size : %d, Real Size : %d", 
				username, SALT_LEN, salt_len);
	} 
	
	else if(err == MYSQL_NO_DATA){
		mysql_log_error("(Username : %s) : There is no row associated "
				"to the given username", username);
		return DB_DENIED;
	}

	return DB_FAILURE;
}

#ifdef TLS_PSK
int mysql_fetch_psk_key(const char * identity, char * iv, char * key)
{
	MYSQL_BIND psk_query_bind[1], psk_result_bind[2];
	int length[2], error[2];

	_mysql_stmt_bind_param(set.stmt_psk, psk_query_bind, 1,
		MYSQL_TYPE_STRING, identity, strlen(identity));

	_mysql_stmt_bind_result(set.stmt_psk, psk_result_bind, 2,
		MYSQL_TYPE_BLOB, iv, IV_LEN, length, error, NULL,
		MYSQL_TYPE_BLOB, key, KEY_LEN, length+1, error+1, NULL
		);

	mysql_stmt_execute(set.stmt_psk);	
	int err = mysql_stmt_fetch(set.stmt_psk);

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
			       " %s", identity, mysql_stmt_errno(set.stmt_psk)); 
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
#endif //TLS_PSK
