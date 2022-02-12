#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/stat.h>

#define EXIT_HELP 2

int
main(int argc, char *argv[])
{
    int flag_verbose = 0;
    char *filter_user = NULL;
    char *filter_execname = NULL;

    char opt;
    while ((opt = getopt(argc, argv, "vf:u:")) > 0) {
        switch (opt) {
            case 'f':
                filter_execname = optarg;
                break;
            case 'u':
                filter_user = optarg;
                break;
            case 'v':
                flag_verbose = 1;
                break;
            case '?': 
            default:
                printf("Try to run without arguments for usage. \n");
                return EXIT_HELP;
        }
    }
    
    if (argc <= 1 || !filter_execname) {
        printf("Usage: %s OPTIONS \n\n", argv[0]);
        printf("OPTIONS:\n"
                "\t-v: Verbose. Shows process names.\n"
                "\t-f <keyword>: Find. Indicates keyword to search with. Required!\n"
                "\t-u <user>: Filter with user\n");
        return EXIT_HELP;
    }

    DIR *proc = opendir("/proc");
    if (!proc) { 
        perror("/proc");
        return EXIT_FAILURE; 
    }

    char line[128];
    char link_path[128];
    char real_username[128];
    char link_realpath[128];
    char item_processname[128];
    char status_file_path[128];
    char proc_current_item[128];
    FILE *status_file;
    struct dirent *dirent;
    while ((dirent = readdir(proc))) {
        if (dirent->d_name[0] == '.') continue;  // 

        status_file = NULL;

        int pid = atoi(dirent->d_name); 
        if (pid == 0) continue;

        snprintf(proc_current_item, 127, "/proc/%s", dirent->d_name);

        struct stat item_stat;
        if (stat(proc_current_item, &item_stat) < 0) {
            if (flag_verbose) perror("stat");
            goto end;
        }
        if ((item_stat.st_mode & S_IFMT) != S_IFDIR) goto end;

        snprintf(link_path, 127, "%s/exe", proc_current_item);
        if (!realpath(link_path, link_realpath)) goto end;

        snprintf(status_file_path, 127, "%s/status", proc_current_item);
        status_file = fopen(status_file_path, "r");
        if (!status_file) {
            if (flag_verbose) perror(status_file_path); 
            goto end;
        }
        
        if (filter_user || flag_verbose) {
            int uid = 0;
            while (fgets(line, 128, status_file)) {
                if (flag_verbose) sscanf(line, "Name:%*[ \t]%[^\t\n]\n", item_processname); 
                if (sscanf(line, "Uid:%*[ \t]%d", &uid) > 0) break; // break after getting Uid
            }

            strncpy(real_username, getpwuid(uid)->pw_name, 127);
            if (filter_user && strncmp(real_username, filter_user, 128) != 0) {
                goto end;
            }

        }

        if (strstr(link_realpath, filter_execname)) {
            if (flag_verbose && !filter_user) { // verbose, not filtered
                printf("%d: %s (%s) [%s]\n", 
                        pid, link_realpath, item_processname, real_username); 
            }
            else if (filter_user && flag_verbose) { // verbose, filtered
                printf("%d: %s (%s)\n", pid, link_realpath, item_processname);
            }
            else { // else (not verbose)
                printf("%d\n", pid);
            }
        }


end:
        if (status_file) fclose(status_file);
    }

    closedir(proc);
    
    return EXIT_SUCCESS;
}

