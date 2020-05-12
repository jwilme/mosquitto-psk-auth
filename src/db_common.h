#pragma once 

enum DB_ErrorCodes {
	DB_SUCCESS = 0,
	DB_FAILURE = 1,
};

#define SALT_QUERY "SELECT salt FROM credentials WHERE username=?"

#define PSK_CLIENT_QUERY "SELECT cyphered_PSK,init_Vector \
	FROM psk WHERE identity=?"

#define UNPWD_CLIENT_QUERY "SELECT COUNT(userID) FROM credentials WHERE \
	username=? AND password_hash=?"

#define ACL_SUB_QUERY  ""	
#define ACL_PUB_QUERY  ""
#define ACL_READ_QUERY ""
