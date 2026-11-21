#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(void){
    /* exact heap end: place 4-byte alloc at end of a fresh mmap so ANY read past 4 faults */
    size_t pg = 4096;
    char *base = mmap(NULL, pg*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    mprotect(base+pg, pg, PROT_NONE);
    char *p = base + pg - 4;   /* 4-byte buffer flush against a PROT_NONE guard */
    memset(p, 'A', 4);
    char user_val[16];
    int cnt = sscanf(p, "%s", user_val);   /* reads past p[3] -> SIGSEGV under guard */
    printf("cnt=%d\n", cnt);
    fflush(stdout);
    _exit(0);
}
