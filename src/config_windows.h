/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#if defined(__cplusplus)
extern "C" {
#endif

#define VERSION "3.26"
#define _CRT_SECURE_NO_WARNINGS 1

#pragma  comment(lib, "wsock32.lib")

#include "winsock2.h"
#include "WS2tcpip.h"
#include "io.h"

#define u_char UCHAR
#define uchar UCHAR

#define u_int8_t UCHAR
#define uint8_t UCHAR
#define int8_t CHAR

#define u_int16_t WORD
#define uint16_t WORD
#define int16_t WORD

#define u_int32_t UINT32
#define uint32_t UINT32
#define int32_t INT32

#define u_int64_t UINT64
#define uint64_t UINT64
#define int64_t INT64

#if defined(__cplusplus)
#define strdup _strdup
#define setmode _setmode
#define snprintf _snprintf_s
#endif

#if defined(__cplusplus)
}  /* extern "C" */
#endif
