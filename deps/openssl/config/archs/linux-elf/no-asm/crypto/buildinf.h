/*
 * WARNING: do not edit!
 * Generated by util/mkbuildinf.pl
 *
 * Copyright 2014-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define PLATFORM "platform: linux-elf"
#define DATE "built on: Tue Jan 14 01:42:10 2020 UTC"

/*
 * Generate compiler_flags as an array of individual characters. This is a
 * workaround for the situation where CFLAGS gets too long for a C90 string
 * literal
 */
static const char compiler_flags[] = {
    'c','o','m','p','i','l','e','r',':',' ','g','c','c',' ','-','f',
    'P','I','C',' ','-','p','t','h','r','e','a','d',' ','-','W','a',
    'l','l',' ','-','O','3',' ','-','f','o','m','i','t','-','f','r',
    'a','m','e','-','p','o','i','n','t','e','r',' ','-','D','O','P',
    'E','N','S','S','L','_','U','S','E','_','N','O','D','E','L','E',
    'T','E',' ','-','D','L','_','E','N','D','I','A','N',' ','-','D',
    'O','P','E','N','S','S','L','_','P','I','C',' ','-','D','N','D',
    'E','B','U','G','\0'
};
