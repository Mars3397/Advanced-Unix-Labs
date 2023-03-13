#include <stdio.h>
#include <string.h>
#include <dirent.h>

void check_dir(char *path, char *magic_number) {
    DIR *dp;
    struct dirent *dirp;

    if ((dp = opendir(path)) == NULL) {
        fprintf(stderr, "Cannot open \"%s\". \n", path);
        return;
    }

    while ((dirp = readdir(dp)) != NULL) {
        if (strcmp(".", dirp->d_name) == 0 || strcmp("..", dirp->d_name) == 0) {
            continue;
        }

        char full_path[1024];
        memset(full_path, 0, 1024);
        strcpy(full_path, path);
        strcat(full_path, "/");
        strcat(full_path, dirp->d_name);

        if (dirp->d_type != DT_DIR) {
            FILE *target;
            char line[1024];

            target = fopen(full_path, "r");
            if (target == NULL) {
                fprintf(stderr, "Cannot open file. \n");
                return;
            }

            size_t nb = fread(line, sizeof(char), 1024, target);
            if (nb == -1) {
                fprintf(stderr, "Read file error. \n");
            }

            if (strncmp(line, magic_number, sizeof(magic_number)) == 0) {
                printf("%s\n", full_path);
            }
        } else if (dirp->d_type == DT_DIR) {
            check_dir(full_path, magic_number);
        }
    }

    closedir(dp);
    return;
}

int main(int argc, char *argv[]) {
    char *path = argv[1];
    char *magic_number = argv[2];

    check_dir(path, magic_number);

    return 0;
}