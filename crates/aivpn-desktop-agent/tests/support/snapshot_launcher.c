#include <unistd.h>
#include <stdio.h>
int main(int argc,char **argv) {
    (void)argc;
    argv[0]="/usr/bin/python3";
    execv(argv[0],argv);
    perror("execv");
    return 111;
}
