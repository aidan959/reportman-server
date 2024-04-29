

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

char* join_paths(const char* path1, const char* path2) {

    if (path1 == NULL || path2 == NULL)
        return NULL;

    size_t len1 = strlen(path1);
    size_t len2 = strlen(path2);
    char *result = malloc(len1 + len2 + 2); 

    if (result == NULL) {
        return NULL;
    }

    strcpy(result, path1);
    if (len1 > 0 && result[len1 - 1] != '/' && path2[0] != '/') {
        strcat(result, "/");
    }
    strcat(result, path2);

    return result;
}

void split_path(const char *path, char **directory, char **filename) {
    if (path == NULL) return;

    char *last_slash = strrchr(path, '/');  
    if (last_slash == NULL) {

        *directory = strdup("");
        *filename = strdup(path);
    } else {
        size_t dir_length = (size_t)last_slash - (size_t)path + 1;
        *directory = (char *)malloc(dir_length + 1);
        if (*directory) {
            strncpy(*directory, path, dir_length);
            (*directory)[dir_length] = '\0'; 
        }
        *filename = strdup(last_slash + 1);
    }
}


int create_directory_if_not_exists(const char* directory_name) {
    struct stat st;

    // Check if the directory exists
    if (stat(directory_name, &st) == -1) {
        // Directory doesn't exist, create it
        if (mkdir(directory_name, 0777) == -1) {
            // Error creating directory
            perror("mkdir");
            return 1; // Return error code
        }
        printf("Directory created successfully.\n");
    } else {
        // Directory already exists
        printf("Directory already exists.\n");
    }

    return 0; // Return success code
}