#include <stdio.h>
#include <stdlib.h>

#include <access-db.h>
#include <privilege-control.h>
#include <common.h>

int main(int argc, char * argv[])
{
    FILE * log_file = NULL;
    char ** installed_app_list = NULL;
    int app_list_len = 0;
    int i = 0;
    int ret = 0;

    log_file = fopen("/root/rules_loader_log.txt", "w");
    if (log_file == NULL)
        goto error;
    fprintf(log_file, "Loading rules for all installed apps:\n");

    //getting app list from database
    ret = get_all_apps_ids(&installed_app_list, &app_list_len);
    if (ret != PC_OPERATION_SUCCESS) {
        fprintf(log_file, "Unable to load applications list!\n);");
        ret = -1;
        goto error;
    }

    //checking if database is not empty
    if (app_list_len == 0) {
        fprintf(log_file, "App database empty, no apps installed\n");
        goto error;
    }

    //loading rules for each app
    for (i = 0; i < app_list_len; i++) {
        fprintf(log_file, "Loading rules for app_id: %s...\n", installed_app_list[i]);

        //checking if rules are loaded
        ret = check_if_rules_were_loaded(installed_app_list[i]);
        if (ret < 0) {
            fprintf(log_file,"Error in check_if_rules_were_loaded()\n");
            //we skipping to the next app_id
        } else if (ret == 0) {
            //if not load rules
            ret = add_app_first_run_rules(installed_app_list[i]);
            if (ret < 0)
                fprintf(log_file,"Error in add_app_first_run_rules()\n");
            else
                //mark rules as loaded
                mark_rules_as_loaded(installed_app_list[i]);
        } else {
            fprintf(log_file,"Rules already loaded\n");
        }

        fprintf(log_file, "DONE\n");
    }

   ret = add_app_first_run_rules("email-service");
   if (ret < 0)
       fprintf(log_file,"Error in add_app_first_run_rules()\n");
   else
       //mark rules as loaded
       mark_rules_as_loaded("email-service"); 

   ret = add_app_first_run_rules("contacts-service");
   if (ret < 0)
       fprintf(log_file,"Error in add_app_first_run_rules()\n");
   else
       //mark rules as loaded
       mark_rules_as_loaded("contacts-service"); 

error:
    //cleaning up
    if (installed_app_list != NULL) {
        for (i = 0; i < app_list_len; i++)
            free(installed_app_list[i]);
        free(installed_app_list);
    }

    if (log_file)
        fclose(log_file);
    return ret;
}
