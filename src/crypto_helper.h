#pragma once

typedef enum Crypto_ErrorCodes {
	CRYPTO_OK = 0,
	CRYPTO_FAILURE = 1
}

#define KEY_LEN 32
#define HASH_LEN 32
#define SALT_LEN 16
#define IV_LEN 16

#define T_COST 4
#define M_COST 12
#define PARA_COST 1

int hash_password(const char * password, const char * salt, char * hash);
int compute_master_key(const char * password, char * out);
int decypher_key(const char * key, const char * cypher, const char * iv,  char * out_key); 

