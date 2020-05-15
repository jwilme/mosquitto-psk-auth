#pragma once 

enum DB_ErrorCodes {
	DB_SUCCESS = 0,
	DB_FAILURE = 1,
};


typedef int 	(*DB_init)(void);
typedef int 	(*DB_connect)(const char *, const char *);
typedef void 	(*DB_disconnect)(void);
typedef void 	(*DB_cleanup)(void);
typedef void 	(*DB_prepare_statements)(void);
typedef void 	(*DB_close_statements)(void);
typedef int 	(*DB_pw_check)(const char *, const char *, long long int *);
typedef int 	(*DB_get_salt)(const char *, char *); 
typedef int 	(*DB_fetch_psk_key)(const char *, char *, char *);

struct DB_instance{
	DB_init init;
	DB_connect connect;
	DB_disconnect disconnect;
	DB_cleanup cleanup;
	DB_prepare_statements prepare_statements; 
	DB_close_statements close_statements;
	DB_pw_check pw_check; 
	DB_get_salt get_salt; 
	DB_fetch_psk_key fetch_psk_key;
};

#define SALT_QUERY "SELECT salt FROM credentials WHERE username=?"

#define PSK_CLIENT_QUERY "SELECT cyphered_PSK,init_Vector \
	FROM psk WHERE identity=?"

#define UNPWD_CLIENT_QUERY "SELECT COUNT(userID) FROM credentials WHERE \
	username=? AND password_hash=?"

#define ACL_SUB_QUERY  ""	
#define ACL_PUB_QUERY  ""
#define ACL_READ_QUERY ""
