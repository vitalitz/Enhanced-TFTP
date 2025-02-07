#ifndef MD5_UTILS_H
#define MD5_UTILS_H

#include <stdint.h>

void compute_md5(const char *filename, uint8_t hash[16]);

#endif