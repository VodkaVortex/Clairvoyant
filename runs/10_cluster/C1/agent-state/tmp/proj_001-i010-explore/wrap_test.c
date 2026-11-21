#include <stdio.h>
#include <stdint.h>
int main(void) {
    unsigned int data_rate = 268435456; /* 2^28 = UINT_MAX/8 + 1 */
    unsigned int scaled = data_rate * 16;
    printf("scaled=0x%x\n", scaled); /* 2^28*16 = 2^32 -> 0 */
    return 0;
}
