//
// Created by parallax on 2024/9/7.
//

#ifndef PARALLAX_PARALLAX_STRING_H
#define PARALLAX_PARALLAX_STRING_H

#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif
int parallax_memcmp(const void *cs, const void *ct, size_t count);
size_t parallax_strlen(const char *s);
char *parallax_strstr(const char *s1, const char *s2);
int parallax_strncasecmp(const char *s1, const char *s2, size_t n);
#ifdef __cplusplus
};
#endif
#endif //PARALLAX_PARALLAX_STRING_H
