#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void){
    // Simulate kmalloc(4): ASan poisons after 4 bytes of a 4-byte alloc
    char *p = malloc(4); memset(p, 'A', 4);
    char user_val[16];
    int cnt = sscanf(p, "%s", user_val);  // %s scans until NUL
    printf("cnt=%d first=%c len=%zu\n", cnt, user_val[0], strlen(user_val));
    free(p);
    return 0;
}
