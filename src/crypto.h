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
#define SALT_LEN 32
#define IV_LEN 16

#define T_COST (uint32_t)(4)
#define M_COST (uint32_t)(4096)
#define PARA_COST (uint32_t)(1)


/*
 * Function: hash_password
 *
 * This function takes a password, concatenate the salt at the end of it, and
 * compute the Argon2 Hash. The point of generating such a hash is to check
 * if the couple username/password given by the client matches the one 
 * stored in the databse, without ever storing the password in plaintext.
 *
 * Parameters:
 *	password:	Pointer to the C-String containing the password that 
 *			needs to be hashed	
 *	salt: 		Pointer to the C-String containing the salt to be 
 *			concatenated after the password before the hash 
 *	hash:		An allocated buffer that will contain the resulting 
 *			Argon2 Hash 
 * Return value:
 * 	CRYPTO_OK on success
 * 	CRYPTO_FAILURE if the hash could not be calculated
 *
 * TODO : 
 * 	At the moment, the program only supports Argon2 to hash 
 * 	received password (all this, in the aim to authenticate a MQTT Client). 
 * 	In the future (MAYBE), it may be possible to choose other hash algorithm 
 * 	such as PBKDF2 or Bcrypt
 *
 * 	It may also be possible to store in the DB the parameters of the 
 * 	hash.
 */
int hash_password(const char * password, const char * salt, char * hash);

/*
 * Function: compute_master_key
 *
 * This functions takes a password and a salt, concatenate both and hash the
 * resulting string using SHA256. The point is to generate with a user-typed
 * password and a randomly generated salt a 256 bits keys that is going to be
 * used to uncypher stored PSK.  
 *
 * Parameters: 
 * 	password:	A pointer to a C-String containing the user-typed 
 * 			password
 * 	salt:		A pointer to a C-String containing the random generated
 * 			salt
 * 	out:		A pointer to an allocated buffer which will contain the
 * 			resulting hash (the psk master key)
 *
 * Return Value: 
 * 	CRYPTO_OK if the hash could be genereated properly
 * 	CRYPTO_FAILURE if not (e.g. a malloc failed)
 *
 * TODO:
 * 	For the moment, this functions only support the SHA256 algorithm. In
 * 	the future, it could be interesting to support type of hash such as 
 * 	MD5 (booo) or SHA3, SHA512 depending on the wanted length of the 
 * 	key.
 */
int compute_master_key(const char *password, const char *salt, char *out);

/*
 * Function: decypher_key
 *
 * This function takes a cyphered key and its init vector and uncyphers 
 * it using the AES256_CBC algorithm
 *
 * Parameters:
 *	key: 		The Master-Key used to cypher/decypher the cyphered key
 *	cypher: 	The Cyphered Key
 *	iv: 		The Init Vector used to cypher the Key
 *	out_key: 	The Uncyphered KEY
 *
 * Return Value:
 *	CRYPTO_OK if the psk has been successfully decyphered 
 *	CRYPTO_FAILURE otherwise 
 *
 * TODO:
 * 	At the moment, the only algorithm supported is AES256_CBC, it could be 
 * 	interesting in the future to integrate other cyphers such as Blowfish or
 * 	Triple DES for example. 	
 */
int decypher_key(const char * key, const char * cypher, const char * iv,  char * out_key); 

