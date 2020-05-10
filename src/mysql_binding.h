#pragma once

#define LOCALHOST NULL
#define DB_NAME "test"
#define DB_UNIX_SOCKET "/run/mysqld/mysqld.sock"

#define NO_PORT 0
#define NO_FLAG 0


void mysql_init(void);
void mysql_connect(const char *username, const char *password);
void mysql_disconnect(void);
void mysql_cleanup(void);

void mysql_stmt_bind_param(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, ...);
void mysql_stmt_bind_result(MYSQL_STMT *stmt, MYSQL_BIND *bnd, int row_count, ...);

void mysql_prepare_statements(MYSQL * sql_handler);
void mysql_close_statements(void);

int mysql_pw_check(const char *username, const char *hash_buff, int *p_result);
int mysql_get_salt(const char *username, char *salt_buf);
int mysql_fetch_psk_key(const char *identity, char *iv, char *key);
