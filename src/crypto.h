#pragma once

enum Crypto_ErrorCodes {
	CRYPTO_OK = 0,
	CRYPTO_FAILURE = 1
};

/* Hashing Fuctions for Password Checking :
 *	Implemented : Argon2, 
 *	To be implemented (MAYBE) : PBKDF2, Bcrypt, Scrypt
 *
 * Hashing Functions for Key Generation :
 * 	Implemented : SHA256 + SALT,
 *	To be implemented (MAYBE) : SHA1, MD5
 *
 * Symmetric Cypher for PSK decyphering :
 * 	Implemented : AES256-CBC
 * 	To be implemented (for sure) : AES128-CBC
 * 	To be implemented (MAYBE) : Triple DES, Blowfish
 *
 *
 */
enum Crypto_PwHash {
	ARGON2 = 1
};

enum Crypto_KeyHash {
	SHA_256= 1
};

enum Crpyto_SymCyp {
	AES256_CBC = 1
};

#define KEY_LEN 32
#define HASH_LEN 32
#define SALT_LEN 16
#define IV_LEN 16

#define T_COST 4
#define M_COST 12
#define PARA_COST 1


int hash_password(const char * password, const char * salt, char * hash);

int compute_master_key(const char *password, 
		const char *salt, char *out);

int decypher_key(const char * key, const char * cypher, const char * iv,  char * out_key); 

