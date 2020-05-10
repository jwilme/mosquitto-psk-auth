#pragma once

enum Auth_ErrorCodes {
	AUTH_SUCCESS = 0,
	AUTH_DENIED = 1,
	AUTH_FAILURE = 2,
}

#define MASTER_PSK_USERNAME "master_psk"
#define MAX_PASSWORD_SIZE 40
#define RETRY_LIMITS 3

int db_connection(const char *user, const char *password);
int psk_master_auth(const char *password, char *out_key);
int unpwd_client_auth(const char *username, const char *password);
int psk_client_auth(const char *identity, char *psk_key);
