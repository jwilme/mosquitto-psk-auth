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
 * compute the Argon2 Hash 
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

int decypher_key(const char * key, const char * cypher, 
		const char * iv, char * out_key)
{
	EVP_CIPHER_CTX * ctx;	
	int total_len, len;
	int err; 

	//XXX : wtf is this? Need to read the man page or the header
	if(!(ctx = EVP_CIPHER_CTX_new()))
		return CRYPTO_FAILURE;	

	err = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
				(unsigned char *)key, (unsigned char *)iv);
	if(err){
		//TODO : Log
		//TODO : Jump to clean 
	}	

	err = (!EVP_DecryptUpdate(ctx, out_key, &len, cypher, KEY_LEN));
	if(err){
		//TODO : Log
		//TODO : Jump to clean 
	}	

	total_len = len;

	err = EVP_DecryptFinal_ex(ctx, out_key + len, &len);
	if(err){
		//TODO : Log
		//TODO : Jump to clean 
	}	

	total_len += len;
	if(total_len != KEY_LEN){
		//TODO Set err
		//TODO Log
	}

	EVP_CIPHER_CTX_free(ctx);
	
	return err ? CRYPTO_FAILURE : CRYPTO_OK;
}
