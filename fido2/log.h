/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 * 
 * This file is part of Solo.
 * 
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 * 
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
 */
#ifndef _LOG_H
#define _LOG_H

#include APP_CONFIG
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
    TAG_GEN = (1 << 0),
    TAG_MC = (1 << 1),
    TAG_GA = (1 << 2),
    TAG_CP = (1 << 3),
    TAG_ERR = (1 << 4),
    TAG_PARSE= (1 << 5),
    TAG_CTAP = (1 << 6),
    TAG_U2F = (1 << 7),
    TAG_DUMP = (1 << 8),
    TAG_GREEN = (1 << 9),
    TAG_RED= (1 << 10),
    TAG_TIME= (1 << 11),
    TAG_HID = (1 << 12),
    TAG_USB = (1 << 13),
    TAG_WALLET = (1 << 14),
    TAG_STOR = (1 << 15),
    TAG_DUMP2 = (1 << 16),
    TAG_BOOT = (1 << 17),
    TAG_EXT = (1 << 17),

    TAG_FILENO = (1U<<31)
} LOG_TAG;

#if DEBUG_LEVEL > 0

void set_logging_mask(uint32_t mask);
#define printf1(tag,fmt, ...) LOG(tag & ~(TAG_FILENO), NULL, 0, fmt, ##__VA_ARGS__)
#define printf2(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define printf3(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define dump_hex1(tag,data,len) LOG_HEX(tag,data,len)

#else

#define set_logging_mask(mask)
#define printf1(fmt, ...)
#define printf2(fmt, ...)
#define printf3(fmt, ...)
#define dump_hex1(tag,data,len)

#endif

#endif
