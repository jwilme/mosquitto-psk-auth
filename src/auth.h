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
typedef int 	(*DB_pw_check)(const char *, const char *, int *);
typedef int 	(*DB_get_salt)(const char *, char *); 
typedef int 	(*DB_fetch_psk_key)(const char *, char *, char *);

struct DB_instance{
	DB_init db_init;
	DB_connect db_connect;
	DB_disconnect db_disconnect;
	DB_cleanup db_cleanup;
	DB_prepare_statements db_prepare_statements; 
	DB_close_statements db_close_statements;
	DB_pw_check db_pw_check; 
	DB_get_salt db_get_salt; 
	DB_fetch_psk_key db_fetch_psk_key;
};

struct Crypto_instance{
	
};

char * psk_master_key;

int auth_init(struct mosquitto_opt * opts, int opt_count);
int auth_connect(void);
int auth_psk_init(char *psk_generated_key);
int psk_master_auth(const char *password, char *out_key);
int unpwd_client_auth(const char *username, const char *password);
int psk_client_auth(const char *identity, char *psk_key);
