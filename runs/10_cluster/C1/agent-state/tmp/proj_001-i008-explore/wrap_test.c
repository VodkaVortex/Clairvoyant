#include <stdio.h>
#include <stdint.h>
static uint32_t crystal_clock_freq = 2500;
int main(void) {
    for (uint32_t k = 0; k < 4; k++) {
        uint32_t speed = 0x20000000u * k; /* k * 2^29 = k * (UINT_MAX/8 rounded) */
        uint32_t denom = 8u * speed;
        printf("k=%u speed=%u (0x%x) 8*speed mod 2^32 = %u%s\n",
               k, speed, speed, denom, denom == 0 ? "  <-- DIVISOR ZERO" : "");
    }
    /* The wrapped-zero speeds are speed = 2^29, 2*2^29, 3*2^29 (and 0) */
    printf("speed=536870912: denom=%u\n", 8u*536870912u);
    printf("speed=1073741824: denom=%u\n", 8u*1073741824u);
    printf("speed=1610612736: denom=%u\n", 8u*1610612736u);
    return 0;
}
