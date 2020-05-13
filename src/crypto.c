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



int hash_password(const char * password, const char * salt, char * hash){
	int pwd_len = strlen(password);
	int salt_len = strlen(salt);

	if(argon2i_hash_raw(T_COST, M_COST, PARA_COST, password, pwd_len, salt, 
			salt_len, hash, HASH_LEN)){
		return CRYPTO_OK;
	}

	return CRYPTO_FAILURE;		
}

int compute_master_key(const char * password, char * out){
	int pwd_len = strlen(password);
	strcpy(out, SHA256(password, pwd_len, NULL)); 

	return CRYPTO_OK;
}

int decypher_key(const char * key, const char * cypher, const char * iv, char * out_key){
	EVP_CIPHER_CTX * ctx;	
	int total_len, len;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		return CRYPTO_FAILURE;	

	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return CRYPTO_FAILURE;
	
	if(!EVP_DecryptUpdate(ctx, out_key, &len, cypher, KEY_LEN))
		return CRYPTO_FAILURE;

	total_len = len;

	if(!EVP_DecryptFinal_ex(ctx, out_key + len, &len))
		return CRYPTO_FAILURE;

	total_len += len;

	if(total_len != KEY_LEN) 
		return CRYPTO_FAILURE;

	EVP_CIPHER_CTX_free(ctx);

	return CRYPTO_OK;	
}
