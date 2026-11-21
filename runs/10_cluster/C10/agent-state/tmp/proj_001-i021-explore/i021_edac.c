#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
typedef unsigned char u8;
#define min_t_(a,b) ((a) < (b) ? (a) : (b))
int faults = 0;
void handle(const char *data, size_t count)
{
    char buf[6];
    u8 len;
    len = min_t_(count, sizeof(buf));   /* s04 line 859 / 307 */
    memcpy(buf, data, len);             /* copy_from_user */
    buf[len] = '\0';                    /* s04 line 863 / 311 */
    printf("count=%zu len=%u terminator_index=%u (buf size %zu)\n", count, len, len, sizeof(buf));
    if (len > sizeof(buf) - 1) { printf("FAULT: terminator index == buffer size -> 1-byte OOB write\n"); faults++; }
}
int main(void) {
    char big[64]; memset(big, 'A', sizeof(big));
    printf("--- s04 pattern: len = min_t(count, sizeof(buf)); buf[len] = 0 ---\n");
    handle(big, 5);   /* in bounds */
    handle(big, 6);   /* len == 6 -> buf[6] = 0 one past the 6-byte stack array */
    handle(big, 100); /* len == 6 -> buf[6] = 0 one past the array */
    printf("faults=%d\n", faults);
    return 0;
}
