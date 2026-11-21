#include <stdio.h>
int main(void){
    unsigned long dr64 = 0x1000000000000000UL; /* 2^60 */
    unsigned int dr32 = 1u<<28; /* 2^28 */
    printf("u64: 2^60*16 = 0x%lx\n", dr64*16);           /* expect 0 */
    printf("u32: 2^28*16 = 0x%x\n", dr32*16);            /* expect 0 */
    unsigned long base_clock = 14745600;
    printf("base_clock %% (dr64*16) would divide by 0x%lx\n", dr64*16);
    (void)base_clock;
    return 0;
}
