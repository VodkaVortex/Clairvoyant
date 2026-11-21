#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void){
    // simulate kmalloc(4) slab: 8-byte usable region, guard after
    char *p = malloc(8); memset(p, 'A', 8);
    char user_val[16];
    int cnt = sscanf(p, "%s", user_val);
    printf("cnt=%d first=%c\n", cnt, user_val[0]);
    free(p); return 0;
}
