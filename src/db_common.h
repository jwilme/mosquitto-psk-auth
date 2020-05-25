#pragma once 

enum DB_ErrorCodes {
	DB_SUCCESS = 0,
	DB_FAILURE = 1,
	DB_DENIED = 2
};


typedef int 	(*DB_connect)(void);
typedef void 	(*DB_disconnect)(void);
typedef void 	(*DB_cleanup)(void);
typedef int 	(*DB_pw_check)(const char *, const char *, long long int *);
typedef int 	(*DB_get_salt)(const char *, char *); 
#ifdef TLS_PSK
	typedef int 	(*DB_fetch_psk_key)(const char *, char *, char *);
#endif

/*
 * Structure: Settings_layout
 *
 * In this plugin, a configuration structure (not a Settings_layout structure) 
 * is a structure that belongs to an entity (e.g : a certain back-end) in which
 * settings are regrouped by their type. 
 *
 * Example of a config structure that can be used :
 *
 * struct dummy_setting_struct{
 * 	SOME_TYPE dummy1;
 * 	SOME_OTHER_TYPE dummy2;
 *
 * 	char *str_setting1;
 * 	char *str_setting2;
 * 	[...]
 * 	char *str_settingN;
 *
 * 	int int_setting1;
 * 	int int_setting2;
 * 	[...]
 * 	int int_settingN;
 *
 * 	int bool_setting1;
 * 	int bool_setting2;
 * 	[...]
 * 	int bool_setting3;
 *
 * 	ANOTHER_TYPE dummy3
 * };
 *
 * Here, the important thing is that the settings that can be configured 
 * through the config file and of the same type (<XXX>_setting<N>) forms 
 * contiguous block in the memory (we'll call such a block a setting-type 
 * block). It does not matter that two separated setting-type blocks are not 
 * contiguous, or that there are other things in the structure.
 *
 * By having this layout, the code to parse the settings in the 
 * configuration file and to set the settings in the plugin is way easier, and
 * easily reusable. 
 *
 * The Settings_layout structure contains information about the layout of the
 * setting structure. It contains the adress to the first settings of each
 * setting-type block, as well as the count of settings contained in each 
 * setting-type block. 
 *
 * Finally, the Settings_layout structure also has for each setting-block a 
 * pointer to an array of string. Each string represents a valid setting
 * name that can be found in the configuration file. The strings are 
 * ordered so that a str at position i is the name of the setting that will
 * affect the i-th settings of the setting-block type.
 *
 * There are only three types that are accepted from the configuration file :
 * Strings, integers and booleans. 
 *
 * str_setting_cnt : 	the number of parameters of the entity that are strings
 * int_setting_cnt: 	the number of parameters of the entity that are integers
 * bool_setting_cnt: 	the number of parameters of the entity that are bools
 * 
 * str_first: 		a pointer to the first string that can be configured
 * int_first: 		a pointer to the first int that can be configured
 * bool_first: 		a pointer to the first bool (int) that can be configured
 *
 * str_settings: 	an array of strings containing the name of
 * 			the different name of the settings that are strings,
 * 			ordered in the same order that there are declared in
 * 			the configuration structure
 * int_settings: 	an array of strings containing the name of
 * 			the different name of the settings that are int,
 * 			ordered in the same order that there are declared in
 * 			the configuration structure
 * bool_settings: 	an array of strings containing the name of the different
 * 			name of the settings that are strings, ordered in the 
 * 			same order that there are declared in the configuration 
 * 			structure
 */
struct Settings_layout{
	int str_setting_cnt;
	int int_setting_cnt;
	int bool_setting_cnt;

	const char **str_first;
	int *int_first;
	int *bool_first;

	const char **str_settings;
	const char **int_settings;
	const char **bool_settings;

};

struct DB_instance{
	DB_connect connect;
	DB_disconnect disconnect;
	DB_cleanup cleanup;
	DB_pw_check pw_check; 
	DB_get_salt get_salt; 
#ifdef TLS_PSK
	DB_fetch_psk_key fetch_psk_key;
#endif
};

#define SALT_QUERY "SELECT salt FROM %s WHERE username=?;"
#define UNPWD_QUERY "SELECT COUNT(Username) FROM %s WHERE username=? AND pwd_hash=?;"

#ifdef TLS_SPK
	#define PSK_QUERY "SELECT cyph_psk,iv FROM %s WHERE identity=?;"
#endif

#define ACL_SUB_QUERY  ""	
#define ACL_PUB_QUERY  ""
#define ACL_READ_QUERY ""
