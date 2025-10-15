#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void do_input(){
    char buffer[32];
    int key = 0x12345678;
    printf("yes? ");
    fflush(stdout);
    gets(buffer);
    if(key == 0xdeadbeef){
        printf("good job!!\n");
        printf("%04x\n", key);
        fflush(stdout);
    }
    else{
        printf("%04x\n", key);
        printf("...\n");
        fflush(stdout);
    }
}

int main(int argc, char* argv[]){
    do_input();
    return 0;
}
