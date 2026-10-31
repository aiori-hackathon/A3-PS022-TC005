/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/* libFuzzer target for the shared parser: feed it arbitrary bytes, assert it never reads OOB. */
#define SF_USERSPACE
#include <stdint.h>
#include <string.h>
#include "../../bpf/parse.h"

/* Builds a minimal Ethernet frame around fuzzer bytes and parses it both ways. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 14 || size > 2048)
        return 0;
    unsigned char buf[2048];
    unsigned char scratch[SF_QBUF];
    memcpy(buf, data, size);
    struct sf_pkt p;
    memset(&p, 0, sizeof(p));
    sf_parse(0, buf, buf + size, &p, scratch, 1, 0);
    memset(&p, 0, sizeof(p));
    sf_parse(0, buf, buf + size, &p, scratch, 0, 0);
    return 0;
}
