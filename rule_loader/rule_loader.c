#include <stdio.h>
#include <stdlib.h>

#include <access-db.h>
#include <privilege-control.h>
#include <common.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#define LOG_PATH    "/root/rules_loader_log.txt"
#define EARLY_RULES_DIR   "/opt/etc/smack-app/accesses.d"

int main(int argc, char * argv[])
{
    FILE * log_file = NULL;
    int ret = 0;
    //for searching files in directory
    struct dirent *file = NULL;
    DIR *dir = NULL;

    log_file = fopen(LOG_PATH, "w");
    if (log_file == NULL)
        goto error;
    fprintf(log_file, "Loading early rules...\n");

    //opening directory
    dir = opendir(EARLY_RULES_DIR);
    if (dir == NULL) {
        fprintf(log_file, "Error in opendir(): %s\n", strerror(errno));
        goto error;
    }

    //iterate trough files
    while ((file = readdir(dir)) != NULL) {
        //for each file load rules from it
        fprintf(log_file, "Loading rulse from file: %s\n", file->d_name);
        //checking if it is file
        if (file->d_type != DT_REG) {
            fprintf(log_file, "Skipping, not regular file\n");
            continue;
        }
        //checking if rules are loaded
        ret = check_if_rules_were_loaded(file->d_name);
        if (ret < 0) {
            fprintf(log_file,"Error in check_if_rules_were_loaded()\n");
            //we skipping to the next app_id
        } else if (ret == 0) {
            //if not load rules
            ret = add_app_first_run_rules(file->d_name);
            if (ret < 0)
                fprintf(log_file,"Error in add_app_first_run_rules(): %d\n", ret);
            else
                //mark rules as loaded
                mark_rules_as_loaded(file->d_name);
        } else {
            fprintf(log_file,"Rules already loaded\n");
        }

    }

    fprintf(log_file, "DONE\n");

error:
    if (dir != NULL)
        closedir(dir);
    if (log_file)
        fclose(log_file);
    return ret;
}
