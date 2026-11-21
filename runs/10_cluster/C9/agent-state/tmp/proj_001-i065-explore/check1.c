#include <stdio.h>
#include <stdint.h>
int main(void){
    for (uint32_t al = 0; al <= 2; al++) {
        uint32_t buffer_size = al;            // urb->actual_length
        uint32_t copy_len = buffer_size - 3;  // u32 arithmetic
        uint32_t tail_off = buffer_size - 3;
        printf("actual_length=%u: kmalloc(%u), memcpy(buffer+3 <- p_buffer, %u) [0x%x], ps_head read p_buffer+%u\n",
               al, buffer_size, copy_len, copy_len, tail_off);
    }
    return 0;
}
