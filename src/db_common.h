#pragma once 

enum DB_ErrorCodes {
	DB_SUCCESS = 0,
	DB_FAILURE = 1,
	DB_DENIED = 2
};


typedef int 	(*DB_connect)(void);
typedef void 	(*DB_disconnect)(void);
typedef void 	(*DB_cleanup)(void);
typedef int 	(*DB_pw_check)(const char *, const char *, long long int *);
typedef int 	(*DB_get_salt)(const char *, char *); 
#ifdef TLS_PSK
	typedef int 	(*DB_fetch_psk_key)(const char *, char *, char *);
#endif

struct Settings_layout{
	int str_setting_cnt;
	int int_setting_cnt;
	int bool_setting_cnt;

	const char **str_first;
	int *int_first;
	int *bool_first;

	const char **str_settings;
	const char **int_settings;
	const char **bool_settings;

};

struct DB_instance{
	DB_connect connect;
	DB_disconnect disconnect;
	DB_cleanup cleanup;
	DB_pw_check pw_check; 
	DB_get_salt get_salt; 
#ifdef TLS_PSK
	DB_fetch_psk_key fetch_psk_key;
#endif
};

#define SALT_QUERY "SELECT salt FROM %s WHERE username=?;"
#define UNPWD_QUERY "SELECT COUNT(Username) FROM %s WHERE username=? AND pwd_hash=?;"

#ifdef TLS_SPK
	#define PSK_QUERY "SELECT cyph_psk,iv FROM %s WHERE identity=?;"
#endif

#define ACL_SUB_QUERY  ""	
#define ACL_PUB_QUERY  ""
#define ACL_READ_QUERY ""
