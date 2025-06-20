#ifndef UTILS_H
#define UTILS_H

#include "../headers.h"

#define DISCARD_AND_RETURN(data)      \
    do                                \
    {                                 \
        bpf_ringbuf_discard(data, 0); \
        return 0;                     \
    } while (0)

#endif