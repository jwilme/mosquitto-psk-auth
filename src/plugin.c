#include <mysql/mysql.h>
#include <stddef.h>

#include "plugin.h"
#include "mosquitto_plugin.h"

#include "mysql_helper.h"
#include "crypto_helper.h"

/*
 * Function: mosquitto_auth_plugin_version
 *
 * The broker will call this function immediately after loading the plugin to
 * check it is a supported plugin version. Your code must simply return
 * MOSQ_AUTH_PLUGIN_VERSION.
 */
int mosquitto_auth_plugin_version(void){
	return MOSQ_AUTH_PLUGIN_VERSION;
}

/*
 * Function: mosquitto_auth_plugin_init
 *
 * Called after the plugin has been loaded and <mosquitto_auth_plugin_version>
 * has been called. This will only ever be called once and can be used to
 * initialise the plugin.
 *
 * Parameters:
 *
 *	user_data :      The pointer set here will be passed to the other plugin
 *	                 functions. Use to hold connection information for example.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *opts, int opt_count){
	/* For the moment, options have not effect */

	static MYSQL * db_handler = mysql_init(NULL); 	
	
	if(!db_handler){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Could not initialize the database handler\n");
		return PLUGIN_FAILURE;
	}

	user_data = (void *) &db_handler; 
	return PLUGIN_SUCCESS;
}

/*
 * Function: mosquitto_auth_plugin_cleanup
 *
 * Called when the broker is shutting down. This will only ever be called once
 * per plugin.
 * Note that <mosquitto_auth_security_cleanup> will be called directly before
 * this function.
 *
 * Parameters:
 *
 *	user_data :      The pointer provided in <mosquitto_auth_plugin_init>.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count){
	mosquitto_log_printf(MOSQ_LOG_INFO, "The plugin is shutting down, goodbye! \n");
	mysql_library_end();

	return PLUGIN_SUCCESS;
}

/*
 * Function: mosquitto_auth_security_init
 *
 * This function is called in two scenarios:
 *
 * 1. When the broker starts up.
 * 2. If the broker is requested to reload its configuration whilst running. In
 *    this case, <mosquitto_auth_security_cleanup> will be called first, then
 *    this function will be called.  In this situation, the reload parameter
 *    will be true.
 *
 * Parameters:
 *
 *	user_data :      The pointer provided in <mosquitto_auth_plugin_init>.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *	reload :         If set to false, this is the first time the function has
 *	                 been called. If true, the broker has received a signal
 *	                 asking to reload its configuration.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload){
	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			mosquitto_log_printf(MOSQL_LOG_ERR, "Max number of \
					MySQL Authentication Attempt \
					reached\n");
			return PLUGIN_FAILURE;
		}
	
		//Prompt for password in Terminal	
		char * db_password;	
		// XXX XXX XXX : How to prompt for a password a temp disable echo on the terminal?

		// Open connection to the database
		if(mysql_real_connect( (MYSQL *)user_data, NULL, "mqtt_broker", db_password,
		    "test", 0, "/run/mysqld/mysqld.sock",0)){	
			mosquitto_log_printf(MOSQL_LOG_INFO, "Successfully \
					logged in the MySQL Database\n");
			break;
		}

		else{
			mosquitto_log_printf(MOSQ_LOG_ERR, "Connection to \
					the database failed : %s\n",
					mysql_error( (MYSQL *)user_data );
		}
	}

	prepare_statements((MYSQL *)user_data);
	psk_key = (char *)malloc(sizeof(char) * (KEY_LEN + 1));	

	for(int i = 0; i <= RETRY_LIMITS; i++){
		if(i == RETRY_LIMITS){
			mosquitto_log_printf(MOSQ_LOG_ERR, "Max attempt of \
					psk authentication reached\n");
			free(psk_key);
			return PLUGIN_FAILURE;
		}
	
		//Prompt for password in Terminal	
		char * psk_password;	
		// XXX XXX XXX : How to prompt for a password a temp disable echo on the terminal?
		
		if(!psk_master_auth(psk_password, psk_key)) {	
			return PLUGIN_SUCCESS;	
		}
	}
}

/* 
 * Function: mosquitto_auth_security_cleanup
 *
 * This function is called in two scenarios:
 *
 * 1. When the broker is shutting down.
 * 2. If the broker is requested to reload its configuration whilst running. In
 *    this case, this function will be called, followed by
 *    <mosquitto_auth_security_init>. In this situation, the reload parameter
 *    will be true.
 *
 * Parameters:
 *
 *	user_data :      The pointer provided in <mosquitto_auth_plugin_init>.
 *	opts :           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count :      The number of elements in the opts array.
 *	reload :         If set to false, this is the first time the function has
 *	                 been called. If true, the broker has received a signal
 *	                 asking to reload its configuration.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload){
	//Disconnect and reset the MySQL connection
	mosquitto_log_printf(MYSQL_LOG_INFO, "Disconnecting from the database\n");	
	(void)mysql_reset_connection((MQTT *)user_data);
	mysql_close((MQTT *)user_data);

	return PLUGIN_SUCCESS;
}

/*
 * Function: mosquitto_auth_acl_check
 *
 * Called by the broker when topic access must be checked. access will be one
 * of:
 *  MOSQ_ACL_SUBSCRIBE when a client is asking to subscribe to a topic string.
 *                     This differs from MOSQ_ACL_READ in that it allows you to
 *                     deny access to topic strings rather than by pattern. For
 *                     example, you may use MOSQ_ACL_SUBSCRIBE to deny
 *                     subscriptions to '#', but allow all topics in
 *                     MOSQ_ACL_READ. This allows clients to subscribe to any
 *                     topic they want, but not discover what topics are in use
 *                     on the server.
 *  MOSQ_ACL_READ      when a message is about to be sent to a client (i.e. whether
 *                     it can read that topic or not).
 *  MOSQ_ACL_WRITE     when a message has been received from a client (i.e. whether
 *                     it can write to that topic or not).
 *
 * Return:
 *	MOSQ_ERR_SUCCESS if access was granted.
 *	MOSQ_ERR_ACL_DENIED if access was not granted.
 *	MOSQ_ERR_UNKNOWN for an application specific error.
 *	MOSQ_ERR_PLUGIN_DEFER if your plugin does not wish to handle this check.
 */
int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg){
	// XXX : How to check if the client is allowed to publish / subscribe
	// FIXME : For the time being, allow all :
	return MOSQ_ERR_SUCCESS;	
}

/*
 * Function: mosquitto_auth_unpwd_check
 *
 * This function is OPTIONAL. Only include this function in your plugin if you
 * are making basic username/password checks.
 *
 * Called by the broker when a username/password must be checked.
 *
 * Return:
 *	MOSQ_ERR_SUCCESS if the user is authenticated.
 *	MOSQ_ERR_AUTH if authentication failed.
 *	MOSQ_ERR_UNKNOWN for an application specific error.
 *	MOSQ_ERR_PLUGIN_DEFER if your plugin does not wish to handle this check.
 */
int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password){
	// XXX : Hash the Password and Query for the couple username + password + ClientID
	// FIXME : For the time being, allow all :
	return MOSQ_ERR_SUCCESS;	
}

/*
 * Function: mosquitto_psk_key_get
 *
 * This function is OPTIONAL. Only include this function in your plugin if you
 * are making TLS-PSK checks.
 *
 * Called by the broker when a client connects to a listener using TLS/PSK.
 * This is used to retrieve the pre-shared-key associated with a client
 * identity.
 *
 * Examine hint and identity to determine the required PSK (which must be a
 * hexadecimal string with no leading "0x") and copy this string into key.
 *
 * Parameters:
 *	user_data :   the pointer provided in <mosquitto_auth_plugin_init>.
 *	hint :        the psk_hint for the listener the client is connecting to.
 *	identity :    the identity string provided by the client
 *	key :         a string where the hex PSK should be copied
 *	max_key_len : the size of key
 *
 * Return value:
 *	Return 0 on success.
 *	Return >0 on failure.
 *	Return MOSQ_ERR_PLUGIN_DEFER if your plugin does not wish to handle this check.
 */
int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len){
	// XXX : Look for an existing identity in the db, fetch the cyphered key and the, 
	// 	 decypher it and send the hint to the client.
	// FIXME : For the time being, said that it has been a real success.  

	return PLUGIN_SUCCESS;
}


