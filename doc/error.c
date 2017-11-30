#include <stdio.h>

int main()
{
    printf("%s", "Hello world\n");  // on stdout
    fprintf(stdout, "%s", "Hello world\n");  // on stdout
    fprintf(stderr, "%s", "Stack overflow!\n"); // on stderr
    return 0;
}
