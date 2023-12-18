#include "mysqlx/abe/base64.h"
#include <stddef.h>
#include <iostream>

namespace mysqlx{
namespace abe{
namespace base64_utils {

typedef unsigned int uint32;
#define BASE64_ERROR(msg) std::cerr << "base64 error: " << (msg) << std::endl;

unsigned b64_encode(const char* src, unsigned len, char* dst)
{
    char *p = NULL;
    const char *s = NULL, *end = src + len;
    int pos = 2;
    uint32 buf = 0;

    s = src;
    p = dst;

    while (s < end) {
        buf |= (unsigned char)*s << (pos << 3);
        pos--;
        s++;

        /* write it out */
        if (pos < 0) {
            *p++ = _base64[(buf >> 18) & 0x3f];
            *p++ = _base64[(buf >> 12) & 0x3f];
            *p++ = _base64[(buf >> 6) & 0x3f];
            *p++ = _base64[buf & 0x3f];

            pos = 2;
            buf = 0;
        }
    }
    if (pos != 2) {
        *p++ = _base64[(buf >> 18) & 0x3f];
        *p++ = _base64[(buf >> 12) & 0x3f];
        *p++ = (pos == 0) ? _base64[(buf >> 6) & 0x3f] : '=';
        *p++ = '=';
    }

    return p - dst;
}

unsigned b64_decode(const char* src, unsigned len, char* dst)
{
    const char *srcend = src + len, *s = src;
    char* p = dst;
    char c;
    int b = 0;
    uint32 buf = 0;
    int pos = 0, end = 0;

    while (s < srcend) {
        c = *s++;

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            continue;

        if (c == '=') {
            /* end sequence */
            if (!end) {
                if (pos == 2)
                    end = 1;
                else if (pos == 3)
                    end = 2;
                else
                    BASE64_ERROR("(unexpected \"=\")");
            }
            b = 0;
        } else {
            b = -1;
            if (c > 0 && c < 127)
                b = b64lookup[(unsigned char)c];
            if (b < 0)
                BASE64_ERROR("symbol");
        }
        /* add it to buffer */
        buf = (buf << 6) + b;
        pos++;
        if (pos == 4) {
            *p++ = (buf >> 16) & 255;
            if (end == 0 || end > 1)
                *p++ = (buf >> 8) & 255;
            if (end == 0 || end > 2)
                *p++ = buf & 255;
            buf = 0;
            pos = 0;
        }
    }

    if (pos != 0)
        BASE64_ERROR("end sequence");

    return p - dst;
}

unsigned b64_enc_len(unsigned srclen)
{
    return (srclen + 2) / 3 * 4;
}

unsigned b64_dec_len(unsigned srclen)
{
    return srclen / 4 * 3;
}

}
}//namespace mysqlx::abe
}//namespace mysqlx