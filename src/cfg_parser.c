#include <libconfig.h>

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "db_common.h"
#include "mysql_binding.h"
#include "plugin_log.h"
#include "plugin.h"
#include "cfg_parser.h"

/*
 * Function: _set_parameter
 *
 * This function takes a setting from the configuration file, and sets the 
 * corresponding field of the settings structure of the entity currently being
 * configured to the value contained by the setting of the configuration file.
 *
 * Parameters:
 * 	field: 		The setting from the configuration file 
 * 	type:		The type of the value that the setting contains
 * 	cnt:		The number of settings of the entity that is being
 * 			configured and that matches the type of the value
 * 			contained in the <field> argument
 * 	settings:	An array of string representing the possible 
 * 			settings of the entity being configured that matches
 * 			the type of the value of <field> 
 * 	set_map:	The settings_layout structure that describes the
 * 			layout of the settings structure of the entity
 * 			that is being configured 
 *
 * Return Value:
 * 	CFG_SUCCESS 	if the given settings does exist, and the type of the
 * 			setting corresponds to the actual setting
 * 	CFG_FAILURE 	if an error occured, usually if the given setting 
 * 			does not exist, or the configuration type mismatches
 * 			the actual one
 *
 */ 
int _set_parameter(config_setting_t *field, int type,
		int cnt, const char **settings, 
		const struct Settings_layout *set_map)
{  
	const char *name = config_setting_name(field);

	for(int i = 0; i < cnt; i++){
		if(!strcmp(settings[i], name)){	
			if(type == CONFIG_TYPE_INT){
				int *fst = set_map->int_first + i;
				*fst = config_setting_get_int(field);
				return CFG_SUCCESS;
			}
			
			else if(type == CONFIG_TYPE_STRING){
				const char **fst;
				fst = set_map->str_first + i;
				*fst = config_setting_get_string(field);
				return CFG_SUCCESS;
			}

			else if(type == CONFIG_TYPE_BOOL){
				int *fst = set_map->bool_first + i;
				*fst = config_setting_get_bool(field);
				return CFG_SUCCESS;
			}
		}
	}

	plugin_log_error("<%s:%d-%s> : This option does not" 
			"exist.",
			config_setting_source_file(field),
			config_setting_source_line(field),
			name);
	return CFG_ERROR;
}

/*
 * Function: read_paramaters
 *
 * This function configures an entity of the plugin accordingly to the values
 * that are given in a specific configuration group of the config file.
 *
 * Parameters:
 * 	cfg:		A config_t structure that resulted from the reading of
 * 			the config file
 * 	setting_name:	A string containing the name of the configuration group
 * 			that contains the settings needed to configure the 
 * 			entity
 * 	set_map:	A Setting_layout structure describing the setting
 * 			structure of the entity that is being configured 	
 *
 * Return Value :
 * 	CFG_SUCCESS 	if the entity has been properly configured
 * 	CFG_ERROR	if an error occured e.g. an error in the config file or
 * 			an error while configure the entity
 */
int read_parameters(config_t *cfg, const char *setting_name,
		const struct Settings_layout *set_map)
{
	int count;
	config_setting_t * setting = config_lookup(cfg, setting_name);

	/* Fetch the number of settings in the setting group */
	if(setting)
		count = config_setting_length(setting);

	if(setting == NULL || count == 0){
		plugin_log_warning("No configuration given for the chosen "
				"back-end");
		return CFG_SUCCESS;
	}

	/* Treat each settings of the setting group */
	for(int i = 0; i < count; i++){
		config_setting_t *field = config_setting_get_elem(setting, i);
		int type = config_setting_type(field); 

		const char **settings;
		int cnt;
	
		switch(type){
		case(CONFIG_TYPE_INT):
			cnt = set_map->int_setting_cnt;
			settings = set_map->int_settings;
			break;
	
		case(CONFIG_TYPE_STRING):
			cnt = set_map->str_setting_cnt;
			settings = set_map->str_settings;
			break;
		
		case(CONFIG_TYPE_BOOL):
			cnt = set_map->bool_setting_cnt;
			settings = set_map->bool_settings;
			break;
	
		default:
			plugin_log_error("<%s:%d - %s> The type used for this "
					"configuration is not allowed",
					config_setting_source_file(field),
					config_setting_source_line(field),
					config_setting_name(field));

			plugin_log_fatal("Only type INT, STRING or BOOL is "
					"allowed in theconfiguration file");

			return CFG_ERROR;	
		}
		/* Check that the setting exists, and set it to the value 
		 * given in the config file */
		if(_set_parameter(field, type, cnt, settings, set_map))
			return CFG_ERROR;
	}
	return CFG_SUCCESS;
}

int configure_plugin(const char *filename, struct DB_instance *db_i){
	const char *str;

	/* Open and read the configuration file */
	config_t struct_cfg;
	config_t *cfg = &struct_cfg;
	config_init(cfg);

	if(!config_read_file(cfg, filename)){
		plugin_log_error("Could not read configuration from the given "
				"filename");	
		plugin_log_error("%s:%d - %s", config_error_file(cfg),
				config_error_line(cfg), 
				config_error_text(cfg));

		return CFG_ERROR;	
	}

	/* Search for the back_end settings, and check that it corresponds to
	 * an implemented back-end */
	if(config_lookup_string(cfg, "back_end", &str)){
		if(!strcmp(str, "mysql")){
			mysql_cfg_init(db_i);
			read_parameters(cfg, mysql_cfg_setting, &mysql_set_layout);
			return CFG_SUCCESS;
		} else {
			return CFG_ERROR;	
		}
	}
	return CFG_ERROR;
}
