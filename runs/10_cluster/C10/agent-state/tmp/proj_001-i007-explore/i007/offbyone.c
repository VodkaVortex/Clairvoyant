#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[6];
    size_t count = 6; /* user write of exactly sizeof(buf) bytes */
    unsigned char len = (count < sizeof(buf)) ? count : sizeof(buf);
    memcpy(buf, "1,2,3,", 6); /* fills every byte of buf, no NUL inside */
    buf[len] = '\0';  /* len == 6 == sizeof(buf) -> writes buf[6], one past the end */
    printf("len=%u, terminator written at buf[%u]\n", len, len);
    return 0;
}
