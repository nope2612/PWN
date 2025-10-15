#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct Answers {
    char a[24];
};

struct Answers arr[3];

void cr7(){
      if ( a1 == 010120434470 && a2 == 012124444510 && a3 == 016735673567 )
    return system("/bin/bash");
  else
    return fwrite("Nice try!!!", 1uLL, 0xBuLL, _bss_start);
}

int main(){
    int idx = 0;

    puts("Do you like Ronaldo ??");
    puts("1. Yes\n2. No\n");

    scanf("%d", &idx);

    if (idx > 2) {
        puts("Your option is invalid!!!");
        exit(0);
    }

    puts("I believe Ronaldo can win World Cup 2026, how about you??");

    read(0, &arr[idx], sizeof(struct Answers));

    puts("If you like CR7, I think you can solve this challenge!!!");

    return 0;
}
