#pragma once

typedef enum SQL_ErrorCodes {
	ACCESS_GRANTED = 0,
	ACCESS_DENIED = 1,
	ACCESS_FAILURE = 2,
	ACCESS_CRYPTO_FAILURE = 3
}

#define MASTER_PSK_USERNAME "master_psk"

#define SALT_QUERY "SELECT salt FROM credentials WHERE username=?"

#define PSK_CLIENT_QUERY "SELECT cyphered_PSK,init_Vector \
	FROM psk WHERE identity=?"

#define UNPWD_CLIENT_QUERY "SELECT COUNT(userID) FROM credentials WHERE \
	username=? AND password_hash=?"

#define ACL_SUB_QUERY  ""	
#define ACL_PUB_QUERY  ""
#define ACL_READ_QUERY ""

void db_init();
void db_startup();
void db_shutdown();
void db_cleanup();

void prepare_statements(MYSQL * sql_handler);
void close_statements(void);

int psk_master_auth(const char * password, char * out_key);
int psk_client_auth(const char * identity, char * psk_key);
int unpwd_client_auth(const char * username, const char * password);
