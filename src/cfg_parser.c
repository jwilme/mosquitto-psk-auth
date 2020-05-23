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

int _set_parameter(config_setting_t *field, const char *name, int type, 
		int cnt, const char **settings, 
		const struct DB_settings_layout *db_set_map)
{  
	for(int i = 0; i < cnt; i++){
		if(!strcmp(settings[i], name)){	
			if(type == CONFIG_TYPE_INT){
				int *fst = db_set_map->int_first + i;
				*fst = config_setting_get_int(field);
				return CFG_SUCCESS;
			}
			
			else if(type == CONFIG_TYPE_STRING){
				const char **fst;
				fst = db_set_map->str_first + i;
				*fst = config_setting_get_string(field);
				return CFG_SUCCESS;
			}

			else if(type == CONFIG_TYPE_BOOL){
				int *fst = db_set_map->bool_first + i;
				*fst = config_setting_get_bool(field);
				return CFG_SUCCESS;
			}
		}
	}	

	plugin_log_error("<%s:%d-%s> : This option does not" 
			"exist for the given back-end.",
			config_setting_source_file(field),
			config_setting_source_line(field),
			name);
	return CFG_ERROR;
}

int read_be_parameters(config_t *cfg, const char *setting_name,
		const struct DB_settings_layout *db_set_map)
{
	int count;
	config_setting_t * setting = config_lookup(cfg, setting_name);

	if(setting)
		count = config_setting_length(setting);

	if(setting == NULL || count == 0){
		plugin_log_warning("No configuration given for the chosen "
				"back-end");
		return CFG_SUCCESS;
	}

	for(int i = 0; i < count; i++){
		config_setting_t *field = config_setting_get_elem(setting, i);
		const char *name = config_setting_name(field);
		int type = config_setting_type(field); 

		const char **settings;
		int cnt;
	
		switch(type){
		case(CONFIG_TYPE_INT):
			cnt = db_set_map->int_setting_cnt;
			settings = db_set_map->int_settings;
			break;
	
		case(CONFIG_TYPE_STRING):
			cnt = db_set_map->str_setting_cnt;
			settings = db_set_map->str_settings;
			break;
		
		case(CONFIG_TYPE_BOOL):
			cnt = db_set_map->bool_setting_cnt;
			settings = db_set_map->bool_settings;
			break;
	
		default:
			plugin_log_error("<%s:%d - %s> The type used for this "
					"configuration is not allowed",
					config_setting_source_file(field),
					config_setting_source_line(field),
					name);

			plugin_log_fatal("Only type INT, STRING or BOOL is "
					"allowed in theconfiguration file");

			return CFG_ERROR;	
		}

		int err = (_set_parameter(field, name, type, cnt, settings, 
					db_set_map));
		if(err) 
			return CFG_ERROR;
	}
	return CFG_SUCCESS;
}

int configure_plugin(const char *filename, struct DB_instance *db_i){
	const char *str;

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

	if(config_lookup_string(cfg, "back_end", &str)){
		if(!strcmp(str, "mysql")){
			mysql_cfg_init(db_i);
			read_be_parameters(cfg, mysql_cfg_setting, &mysql_set_layout);
			return CFG_SUCCESS;
		} else {
			return CFG_ERROR;	
		}
	}
	return CFG_ERROR;
}
