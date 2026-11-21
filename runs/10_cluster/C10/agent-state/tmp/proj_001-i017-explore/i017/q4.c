#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(void){
    /* kmalloc(4): ASan redzone right after byte 4 */
    char *p = malloc(4); memset(p, 'A', 4);
    char user_val[16];
    int cnt;
    /* vsscanf-based %s skips leading whitespace then copies non-space until NUL */
    cnt = sscanf(p, "%s", user_val);
    printf("cnt=%d first=%c\n", cnt, user_val[0]);
    fflush(stdout);
    free(p);
    _exit(0);
}
