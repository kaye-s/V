#include <stdio.h>
#include <string.h>
void copy_input(char *input) {
    char buffer[10];
    strcpy(buffer, input);
    printf("%s\n", buffer);
}
