#include <mysql/mysql.h>

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdlib.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"

#include "mysql_helper.h"
#include "crypto_helper.h"

MYSQL_STMT * stmt_salt;
MYSQL_STMT * stmt_psk;
MYSQL_STMT * stmt_auth;

void prepare_statements(MYSQL * sql_handler){
	/* Prepare the Salt statement */
	stmt_salt; = mysql_stmt_init(sql_handler); 
	stmt_salt = mysql_stmt_prepare(stmt_salt, SALT_QUERY, strlen(SALT_QUERY));

	/* Prepare the PSK statement */
	stmt_psk = mysql_stmt_init(sql_handler); 
	stmt_psk = mysql_stmt_prepare(stmt, PSK_CLIENT_QUERY, strlen(PSK_CLIENT_QUERY));

	/* Prepare the Authentication statement */
	stmt_auth = mysql_stmt_init(sql_handler); 
	stmt_auth = mysql_stmt_prepare(stmt, UNPWD_CLIENT_QUERY, strlen(UNPWD_CLIENT_QUERY));
}


void close_statements(){
	/* Close all previously prepared statements */
	mysql_log_info("Closing all statements");
	mysql_stmt_close(stmt_salt);
	mysql_stmt_close(stmt_psk);
	mysql_stmt_close(stmt_auth);
}

int psk_master_auth(const char * password, char * out_key){
	char * username = MASTER_PSK_USERNAME;

	switch(unpwd_client_auth( (const char *) username, password)){
	case(ACCESS_DENIED):
		return ACCESS_DENIED;

	case(ACCESS_FAILURE):
		mysql_log_error("MYSQL ERROR : Master PSK login failure");
		return ACCESS_FAILURE;

	case(ACCESS_GRANTED):
		if(compute_master_key(password, out_key)){
			mysql_log_error("MYSQL INFO : Master PSK key \
					computation failed");
			return ACCESS_FAILURE;
		}
		return ACCESS_GRANTED;
	}	
}

int unpwd_client_auth(const char * username, const char * password){

	char fetch_debug_str[MAX_DEBUG_MSG];
	int return_code = 0;

	long salt_length; 
	uint64_t result;
	mysql auth_is_null;	

	/* Binding and Execution of the Salt Prepared Statement */
	char * salt_buffer = (char *)malloc(sizeof(char) * (SALT_LEN+1));
	char * hash_buffer = (char *)malloc(sizeof(char)* (HASH_LEN+1));

	MYSQL_BIND salt_result_bind[1];
	memset(salt_result_bind, 0, sizeof(salt_result_bind));

	salt_result_bind[0].buffer_type=MYSQL_TYPE_BINARY;
	salt_result_bind[0].buffer = salt_buffer;
	salt_result_bind[0].buffer_length = SALT_LENGTH;
	salt_result_bind[0].length = &salt_length;

	mysql_stmt_bind_result(stmt_salt, salt_result_bind);
	mysql_stmt_execute(stmt_salt);	


	/* Fetching the current row (there should only be one, but we are not checking that there
	 * is indeed only one output row) 
	 */  
	switch(mysql_stmt_fetch(stmt_salt)){
	case(0):
		if(salt_length != SALT_LEN){
			mysql_log_error("(Username : %s) The fetched salt is \
					not of the expected size \
					Fetched : %d || Expected : %d",
					username,
					salt_length,
					SALT_LEN);

			return_code = ACCESS_FAILURE;
		}
		break;

	case(1):
		char * err = mysql_stmt_errno(stmt_salt);
		mysql_log_error("(Username : %s) : Result Fetch Error : %s \n", 
				username, 
				err);

		return_code = ACCESS_FAILURE;
		break;
	
	case(MYSQL_DATA_TRUNCATED):
		mysql_log_error("(Username : %s) : The Salt has been truncated \
			       	when fetched\n", 
				username);

		return_code = ACCESS_FAILURE;
		break;

	case(MYSQL_NO_DATA):
		return_code = ACCESS_DENIED
		break;
	}

	// XXX : Will be turned into a goto target
	if(return_code != 0){
		free(salt_buffer);
		free(hash_buffer);
		return return_code;
	}
	//XXX

	/* Hash the password using Argon2 */ 
	if(hash_password(password, salt_buffer, hash_buffer)){
		// XXX Goto unpwd_cleanup
		free(hash_buffer);
		free(salt_buffer);
		return ACCESS_FAILURE;	
	}	

	/* Binding and Execution of the Auth Query  */
	MYSQL_BIND auth_query_bind[1];
	MYSQL_BIND auth_result_bind[1];
	memset(auth_query_bind, 0, sizeof(auth_query_bind));
	memset(auth_result_bind, 0, sizeof(auth_result_bind));

	auth_query_bind[0].buffer_type=MYSQL_TYPE_BINARY;
	auth_query_bind[0].buffer = hash_buffer;
	auth_query_bind[0].buffer_length = strlen(hash_buffer);
	
	auth_result_bind[0].buffer_type=MYSQL_TYPE_LONGLONG;
	auth_result_bind[0].buffer = (char *)&result;
	auth_result_bind[0].is_null = &auth_is_null;	

	mysql_stmt_bind_param(stmt_auth, auth_query_bind);
	mysql_stmt_bind_result(stmt_auth, auth_result_bind);

	mysql_stmt_execute(stmt_auth);

	switch(mysql_stmt_fetch(stmt_auth)){
		case(0):
			if(auth_is_null){
				snprintf(fetch_debug_str, MAX_DEBUG_MSG, "The master hashed password query \
						returned a null row \n");
				return_code = ACCESS_FAILURE;
			}
			break;

		case(1):
			snprintf(fetch_debug_str, MAX_DEBUG_MSG, "MYSQL ERROR (%s) : Result Fetch Error : %s \n", 
					username, mysql_stmt_errno(stmt_auth));
			return_code = ACCESS_FAILURE;
			break;
		
		case(MYSQL_DATA_TRUNCATED):
			//Should not happen
			snprintf(fetch_debug_str, MAX_DEBUG_MSG, "MYSQL ERROR (%s) : The Row Count has been \ 
					truncated when fetched\n", username);
			return_code = ACCESS_FAILURE;
			break;

		case(MYSQL_NO_DATA):
			//Should not happen either, but yeah, whatever
			snprintf(fetch_debug_str, MAX_DEBUG_MSG, "MYSQL INFO : User (%s) not found in the \
					database \n", username);
			return_code = ACCESS_DENIED
			break;
	}

unpwd_cleanup:
	if(return_code != 0){
		mosquitto_log_printf(MOSQ_LOG_WARNING, fetch_debug_str);
		return return_code;
	}

	/* Return ACCESS_GRANTED if there is exactly one row matching the credentials*/ 
	return (result == 1) ? ACCESS_GRANTED : ACCESS_DENIED;
}

int psk_client_auth(const char * master_key, const char * identity, char * psk_key){
	char fetch_debug_str[MAX_DEBUG_MSG];
	int return_code = 0;

	int length[2], error[2];

	char * init_vector = (char *) malloc(sizeof(char) * IV_LEN); 
	char * cyphered_key = (char *) malloc(sizeof(char) * KEY_LEN);

	MYSQL_BIND psk_query_bind[1];
	MYSQL_BIND psk_result_bind[2];

	memset(psk_query_bind, 0, sizeof(psk_query_bind));
	memset(psk_result_bind, 0, sizeof(psk_result_bind));
	
	psk_query_bind[0].buffer_type = MYSQL_TYPE_STRING;
	psk_query_bind[0].buffer = identity;
	psk_query_bind[0].buffer_length = strlen(identity);
	
	psk_result_bind[0].buffer_type=MYSQL_TYPE_BLOB;
	psk_result_bind[0].buffer = init_vector;
	psk_result_bind[0].buffer_length = IV_LEN;
	psk_result_bind[0].length = &length[0];	
	psk_result_bind[0].error = &error[0];	

	psk_result_bind[1].buffer_type=MYSQL_TYPE_BLOB;  
	psk_result_bind[1].buffer = cyphered_key;
	psk_result_bind[1].buffer_length = KEY_LEN;
	psk_result_bind[1].length = &length[1];	
	psk_result_bind[1].error = &error[1];	

	mysql_stmt_bind_param(stmt_psk, psk_query_bind);
	mysql_stmt_bind_result(stmt_psk, psk_result_bind);

	mysql_stmt_execute(stmt_psk);	

	/* Fetching the current row */  
	switch(mysql_stmt_fetch(stmt_psk)){
		case(0):

			if(length[0] != KEY_LEN || length[1] != SALT_LEN){
				snprintf(MOSQ_LOG_WARNING, "PSK key or IV are not the right size\n");
				return_code = ACCESS_FAILURE;
			}
			break;		 

		case(1):
			snprintf(fetch_debug_str, MAX_DEBUG_MSG, ""); 
			return_code = ACCESS_FAILURE;
			break;

		case(MYSQL_DATA_TRUNCATED):
			if(error[0] || error[1]){
				snprintf(fetch_debug_str, MAX_DEBUG_MSG, "PSK key or IV truncated\n");
				return_code = ACCESS_FAILURE;
			}
			return_code = ACCESS_FAILURE;
			break;

		case(MYSQL_NO_DATA):
			snprintf(fetch_debug_str, MAX_DEBUG_MSG, "Empty Result Set from the PSK client query\n");
			return_code = ACCESS_DENIED;
			break;
	}

	if(return_code != 0){
		mosquitto_log_printf(MOSQ_LOG_WARNING, fetch_debug_str); 
		free(init_vector);
		free(cyphered_key);

		return return_code;
	}

	/* Decypher the PSK */
	int decypher_error = decypher_key(master_key, cyphered_key, init_vector, psk_key);
	free(init_vector);
	free(cyphered_key);

	return decypher_error ? ACCESS_FAILURE : ACCESS_GRANTED;	
}
