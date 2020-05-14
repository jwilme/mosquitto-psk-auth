#include <argon2.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"

#include "crypto.h"
#include "plugin_log.h"

#define LOG_CRYPTO_ERROR 	"[CRYPTO - ERROR] ::"
#define LOG_CRYPTO_WARNING 	"[CRYPTO - WARNING] ::"
#define LOG_CRYPTO_INFO 	"[CRYPTO - INFO] ::"

#define crypto_log_error(...) \
	plugin_log(MOSQ_LOG_WARNING, LOG_CRYPTO_ERROR, __VA_ARGS__)

#define crypto_log_warning(...) \
	plugin_log(MOSQ_LOG_ERROR, LOG_CRYPTO_WARNING, __VA_ARGS__)

#define crypto_log_info(...) \
	plugin_log(MOSQ_LOG_INFO, LOG_CRYPTO_INFO, __VA_ARGS__) 


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
int hash_password(const char * password, const char * salt, char * hash){
	int pwd_len = strlen(password);
	int salt_len = strlen(salt);

	if(argon2i_hash_raw(T_COST, M_COST, PARA_COST, password, pwd_len, salt, 
			salt_len, hash, HASH_LEN)){
		return CRYPTO_OK;
	}

	return CRYPTO_FAILURE;		
}

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
int compute_master_key(const char *password, 
		const char *salt, char *out)
{
	int len = strlen(password) + strlen(salt);
	char * conc = (char *)malloc(sizeof(char) * (len));

	if(!conc){
		crypto_log_error("Could not allocate memory for" 
				"Argon2 Hashing");
		return CRYPTO_FAILURE;
	}

	strcpy(conc, password);
	strcat(conc, salt);

	strcpy(out, (char *)SHA256((unsigned char *)conc, len, NULL)); 

	free(conc);

	return CRYPTO_OK;
}

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
int decypher_key(const char * key, const char * cypher, 
		const char * iv, char * out_key)
{
	EVP_CIPHER_CTX * ctx;	
	int total_len, len;
	int err; 

	if(!(ctx = EVP_CIPHER_CTX_new())){
		crypto_log_error("Could not create a new cypher context");
		return CRYPTO_FAILURE;	
	}

	err = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
				(unsigned char *)key, (unsigned char *)iv);
	if(err){
		crypto_log_error("Could not Initiate the Decypher");
		goto decypher_cleanup;
	}	

	err = (!EVP_DecryptUpdate(ctx, (unsigned char *)out_key, &len, 
				(unsigned char *)cypher, strlen(cypher)));
	if(err){
		crypto_log_error("Could not complete the update step of the"
				 "AES decyphering"); 
		goto decypher_cleanup;
	}	

	total_len = len;

	err = EVP_DecryptFinal_ex(ctx, (unsigned char *)(out_key + len), &len);
	if(err){
		crypto_log_error("Could not complete the Final step of AES" 
				 "decyphering");
		goto decypher_cleanup;
	}	

	total_len += len;
	if(total_len != KEY_LEN){
		err = 1;
		crypto_log_error("The generated key is not the right size");
	}

decypher_cleanup:

	EVP_CIPHER_CTX_free(ctx);
	return err ? CRYPTO_FAILURE : CRYPTO_OK;
}
