#ifndef FIX_H
#define FIX_H

#include <math.h>


#define bool int
//typedef _int64 bool;
#define false 0
#define true 1
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef int int32_t;

#ifdef _MSC_VER
typedef unsigned _int64 uint64_t;
typedef _int64 int64_t;
typedef _int64 int64;
#else
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef long long int64;
#endif

#ifndef INT64_MAX
#define INT64_MAX 0x7FFFFFFFFFFFFFFF
#endif
#ifndef UINT64_MAX
#define UINT64_MAX 0xFFFFFFFFFFFFFFFF
#endif
#ifndef INT32_MAX
#define INT32_MAX ((int32_t)0x7FFFFFFF)
#endif
#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)0xFFFFFFFF)
#endif

#ifndef INT32_MIN
#define INT32_MIN (-INT32_MAX - 1L)
#endif
#ifndef INT64_MIN
#define INT64_MIN (-INT64_MAX - 1L)
#endif

#endif
