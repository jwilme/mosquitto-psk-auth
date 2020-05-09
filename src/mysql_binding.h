#pragma once

void mysql_init(void **user_data);
void mysql_startup(void *user_data);
void mysql_shutdown(void *user_data);
void mysql_cleanup(void);

void mysql_stmt_bind_param(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, ...);
void mysql_stmt_bind_result(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, ...);

void mysql_prepare_statements(MYSQL * sql_handler);
void mysql_close_statements(void);

int mysql_pw_check(const char *username, const char *hash_buff, int *p_result);
int mysql_get_salt(const char *username, char *salt_buf);
int mysql_fetch_psk_key(const char *identity, char *iv, char *key);
