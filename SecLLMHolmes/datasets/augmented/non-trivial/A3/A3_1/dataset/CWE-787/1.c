#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int non_vulnerable_func()
{
    int buf[3];

    buf[0] = 167;
    buf[1] = 249;
    buf[2] = 367;
    buf[3] = 412;

    return 0;
}
