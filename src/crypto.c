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
	plugin_log(LOG_CRYPTO_ERROR, __VA_ARGS__)

#define crypto_log_warning(...) \
	plugin_log(LOG_CRYPTO_WARNING, __VA_ARGS__)

#define crypto_log_info(...) \
	plugin_log(LOG_CRYPTO_INFO, __VA_ARGS__) 


int hash_password(const char * password, const char * salt, char * hash){
	int pwd_len = strlen(password);
	int salt_len = strlen(salt); 
	char tmp[HASH_LEN];

	if(argon2i_hash_raw(T_COST, M_COST, PARA_COST, password, pwd_len, salt, 
			salt_len, tmp, HASH_LEN) == ARGON2_OK){

		for(int i = 0; i< HASH_LEN; i++){
			sprintf(hash + 2*i, "%02x", ((uint8_t *)tmp)[i]);
		}
		return CRYPTO_OK;
	}

	crypto_log_error("Could not hash the password using Argon2");
	return CRYPTO_FAILURE;		
}

int compute_master_key(const char *password, const char *salt, char *out)
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
