#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vulnerable_func()
{
    int buf[3];

    buf[0] = 167;
    buf[1] = 249;
    buf[2] = 367;

    return 0;
}
