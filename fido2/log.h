// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _LOG_H
#define _LOG_H

#ifdef APP_CONFIG
#include APP_CONFIG
#endif

#include <stdint.h>

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#define ENABLE_FILE_LOGGING

void LOG(uint32_t tag, const char * filename, int num, const char * fmt, ...);
void LOG_HEX(uint32_t tag, uint8_t * data, int length);

void set_logging_tag(uint32_t tag);

typedef enum
{
    TAG_GEN      = (1UL << 0UL),
    TAG_MC       = (1UL << 1UL),
    TAG_GA       = (1UL << 2UL),
    TAG_CP       = (1UL << 3UL),
    TAG_ERR      = (1UL << 4UL),
    TAG_PARSE    = (1UL << 5UL),
    TAG_CTAP     = (1UL << 6UL),
    TAG_U2F      = (1UL << 7UL),
    TAG_DUMP     = (1UL << 8UL),
    TAG_GREEN    = (1UL << 9UL),
    TAG_RED      = (1UL << 10UL),
    TAG_TIME     = (1UL << 11UL),
    TAG_HID      = (1UL << 12UL),
    TAG_USB      = (1UL << 13UL),
    TAG_WALLET   = (1UL << 14UL),
    TAG_STOR     = (1UL << 15UL),
    TAG_DUMP2    = (1UL << 16UL),
    TAG_BOOT     = (1UL << 17UL),
    TAG_EXT      = (1UL << 18UL),
    TAG_NFC      = (1UL << 19UL),
    TAG_NFC_APDU = (1UL << 20UL),
    TAG_CCID     = (1UL << 21UL),
    TAG_CM       = (1UL << 22UL),
    TAG_BUTTON   = (1UL << 26UL),

    TAG_NO_TAG   = (1UL << 30UL),
    TAG_FILENO   = (1UL << 31UL)
} LOG_TAG;

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0

void set_logging_mask(uint32_t mask);
#define printf1(tag,fmt, ...) LOG(tag & ~(TAG_FILENO), NULL, 0, fmt, ##__VA_ARGS__)
#define printf2(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define printf3(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define _dump_hex1(tag,data,len) LOG_HEX(tag,data,len)
#define dump_hex1(tag, data, len) printf1(((tag)|TAG_NO_TAG), "%s[%d]: ", #data, len); _dump_hex1(tag, ((uint8_t *) (data)), len);
#define dump_arr(tag, data) printf1(tag,"Dump of %20s: ", #data); _dump_hex1(tag, data, sizeof(data));
#define dump_arrl(tag, data, len) printf1(tag,"Dump of %20s: ", #data); _dump_hex1(tag, data, len);
uint32_t timestamp();

#else

#define set_logging_mask(mask)
#define printf1(tag,fmt, ...)
#define printf2(tag,fmt, ...)
#define printf3(tag,fmt, ...)
#define dump_hex1(tag,data,len)
#define dump_arr(tag, data)
#define dump_arrl(tag, data, len)
#define timestamp()

#endif

#endif
