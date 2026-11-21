#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void){
    char buf[6];
    size_t count = 10;
    unsigned char len = (count < sizeof(buf)) ? count : sizeof(buf);
    for (int i=0;i<(int)len;i++) buf[i]='1';
    buf[len] = '\0';   /* terminator index can equal 6 */
    printf("len=%u str=%s\n", len, buf);
    return 0;
}
