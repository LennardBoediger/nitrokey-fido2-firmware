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
    TAG_GEN      = (1 << 0),
    TAG_MC       = (1 << 1),
    TAG_GA       = (1 << 2),
    TAG_CP       = (1 << 3),
    TAG_ERR      = (1 << 4),
    TAG_PARSE    = (1 << 5),
    TAG_CTAP     = (1 << 6),
    TAG_U2F      = (1 << 7),
    TAG_DUMP     = (1 << 8),
    TAG_GREEN    = (1 << 9),
    TAG_RED      = (1 << 10),
    TAG_TIME     = (1 << 11),
    TAG_HID      = (1 << 12),
    TAG_USB      = (1 << 13),
    TAG_WALLET   = (1 << 14),
    TAG_STOR     = (1 << 15),
    TAG_DUMP2    = (1 << 16),
    TAG_BOOT     = (1 << 17),
    TAG_EXT      = (1 << 18),
    TAG_NFC      = (1 << 19),
    TAG_NFC_APDU = (1 << 20),
    TAG_CCID     = (1 << 21),
    TAG_CM       = (1 << 22),
    TAG_WEBCRYPT = (1u << 23u),
    TAG_BUTTON   = (1 << 26),
    TAG_NO_TAG   = (1UL << 30u),
    TAG_FILENO   = (1UL << 31u)
} LOG_TAG;

#define dumpbytes(buf, len)     dump_hex1(TAG_ERR, buf, len)

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0

void set_logging_mask(uint32_t mask);
#define printf1(tag,fmt, ...) LOG(tag & ~(TAG_FILENO), NULL, 0, fmt, ##__VA_ARGS__)
#define printf2(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define printf3(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define _dump_hex1(tag,data,len) LOG_HEX(tag, (void*)(data),len)
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

#define s_assertrc(test_for_true, CODE_ON_ERR)     if (!(test_for_true)) {printf2(TAG_ERR, "assertion failed: '%s' => %s (0x%X)\n", #test_for_true, #CODE_ON_ERR, CODE_ON_ERR); return (CODE_ON_ERR);}

#endif
