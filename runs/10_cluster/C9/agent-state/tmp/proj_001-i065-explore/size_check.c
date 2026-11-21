#include <stdio.h>
#include <stdint.h>
int main(void){
    // approximate packed sizes
    int RR3_DRIVER_MAXLENS = 128, RR3_MAX_SIG_SIZE = 1024;
    printf("sizeof(redrat3_irdata) ~ %d\n", 4+4+2+2+1+1+2+2+1+2*RR3_DRIVER_MAXLENS+RR3_MAX_SIG_SIZE);
    return 0;
}
