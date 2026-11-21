#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv){
    char *p = malloc(4); memset(p, 'A', 4);
    char user_val[16];
    int cnt = sscanf(p, "%s", user_val);
    printf("cnt=%d first=%c len=%zu\n", cnt, user_val[0], strlen(user_val));
    fflush(stdout);
    free(p);
    _exit(0);
}
