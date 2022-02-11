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
    
    if (argc <= 1 || filter_execname == NULL) {
        printf("Usage: %s [OPTIONS...] \n\n", argv[0]);
        printf("OPTIONS:\n"
                "\t-v: Verbose. Shows process names.\n"
                "\t-f <keyword>: Find. Indicates keyword to search with. Required!\n"
                "\t-u <user>: Filter with user\n");
        return EXIT_HELP;
    }

    DIR *proc = opendir("/proc");
    if (proc == NULL) { 
        perror("/proc");
        return EXIT_FAILURE; 
    }

    struct dirent *dirent;
    while ((dirent = readdir(proc)) != NULL) {
        if (dirent->d_name[0] == '.') continue;

        int pid = atoi(dirent->d_name); 
        if (pid == 0) continue;

        char *line = malloc(256);
        char *link_path = malloc(256);
        char *link_realpath = malloc(256);
        char *proc_file_path = malloc(256);
        char *status_file_path = malloc(256);
        FILE *status_file = NULL;

        snprintf(proc_file_path, 255, "/proc/%s", dirent->d_name);

        struct stat item_stat;
        if (stat(proc_file_path, &item_stat) < 0) {
            perror("stat");
            goto end;
        }
        if ((item_stat.st_mode & S_IFMT) != S_IFDIR) goto end;

        snprintf(link_path, 255, "/proc/%s/exe", dirent->d_name);
        if (!realpath(link_path, link_realpath)) goto end;

        snprintf(status_file_path, 255, "/proc/%s/status", dirent->d_name);
        status_file = fopen(status_file_path, "r");
        if (!status_file) {
            perror(status_file_path); 
            goto end;
        }
        
        if (filter_user != NULL) {
            int uid = 0;
            while (fgets(line, 256, status_file) != NULL) {
                if (sscanf(line, "Uid:%*[ \t]%d", &uid) > 0) break;
            }

            char *real_username = getpwuid(uid)->pw_name;
            if (strncmp(real_username, filter_user, 255) != 0) {
                goto end;
            }
        }

        if (strstr(link_realpath, filter_execname) != NULL) {
            if (!flag_verbose) printf("%d\n", pid);
            else printf("%d: %s\n", pid, link_realpath);
        }


end:
        if (status_file) fclose(status_file);
        free(status_file_path);
        free(proc_file_path);
        free(link_realpath);
        free(link_path);
        free(line);
    }
    closedir(proc);
    
    return EXIT_SUCCESS;
}

