#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>


#include "hpack.h"

#define DEBUG 1

#ifdef DEBUG
#   define dprintf(...) printf(__VA_ARGS__)
#else
#   define dprintf(...)
#endif

const char hblock[] = {
    // [+0] :method: PUT
    0x42,
    0x03,
    0x50, 0x55, 0x54,
    // [+5] :scheme: http
    0x86,
    // [+6] indexed header (*unknown*: *unknown*)
    0xc4,
    // [+7] literal with incremental indexing, indexed name (etag: c)
    0x62,
    0x01,
    0x63, // 'c'
    // [+10] literal with incremental indexing, indexed name dynamic (*unknown*: d)
    0x7f, 0x25, // index 100
    0x01,
    0x64, // 'd'
    // [+14] literal with incremental indexing, new name (a: b)
    0x40,
    0x01,
    0x61, // 'a'
    0x01,
    0x62, // 'b'
    // [+19] literal indexed (cache-control: no-cache)
    0x58,
    0x08,
    0x6e, 0x6f, 0x2d, 0x63, 0x61,
    0x63, 0x68, 0x65,
    // [+29] literal (:path: /api-auth/v1/authenticate/username)
    0x04,
    0x22,
    0x2f, 0x61, 0x70, 0x69, 0x2d,
    0x61, 0x75, 0x74, 0x68, 0x2f,
    0x76, 0x31, 0x2f, 0x61, 0x75,
    0x74, 0x68, 0x65, 0x6e, 0x74,
    0x69, 0x63, 0x61, 0x74, 0x65,
    0x2f, 0x75, 0x73, 0x65, 0x72,
    0x6e, 0x61, 0x6d, 0x65
};

struct header {
    char *name;
    char *value;
};

struct header headers[20];
int hindex = 0;

struct priv {
    const char *fptr;
    const char *errptr;
};

void callback(enum hpack_event_e evt, const char *buf, size_t size, void *priv) {
    struct priv *prv = (struct priv *)priv;
    static const char *name = NULL;
    static size_t sz = 0;
    
#ifdef DEBUG
    if(evt == HPACK_EVT_PTR) { dprintf("\n"); }
    dprintf("[%8s] ", hpack_event_id(evt));

    if(evt == HPACK_EVT_FIELD) {
        dprintf("size=0x%02x (%d)\n", size, size);
    
    } else if(evt == HPACK_EVT_INDEX) {
        dprintf("index=%02x (%d) size=%02x (%d)\n", (size_t)buf, (size_t)buf, size, size);
    
    } else
#endif
    if(evt == HPACK_EVT_PTR) {
        prv->fptr = buf;
        prv->errptr = NULL;
        dprintf("%p[+%d]=0x%02x\n", buf, buf - hblock, (uint8_t)*buf);
    
    } else if(evt == HPACK_EVT_RECERR) {
        prv->errptr = buf;
        dprintf("%p[+%d]=0x%02x idx=%d\n", buf, buf - hblock, (uint8_t)*buf, size);
    
    } else
    if(evt == HPACK_EVT_NAME) {
        name = buf;
        sz = size;
    } else if(evt == HPACK_EVT_VALUE) {
        if(prv->errptr && !(name == hpack_unknown_name || buf == hpack_unknown_value)) {
            printf("E: %*s: %*s    [%d/%d]\n", sz, name, size, buf, name == hpack_unknown_name, buf == hpack_unknown_value);
            //exit(1);
        }
        dprintf("   %*s: %*s\n", sz, name, size, buf);
        if(!prv->errptr) {
            headers[hindex].name = strndup(name, sz);
            headers[hindex].value = strndup(buf, size);
            ++hindex;
        }
        prv->errptr = NULL;
    }
#ifdef DEBUG
    else if(buf != NULL) {
        dprintf("%*s\n", size, buf);
    
    } else {
        dprintf("%02x (%d)\n", size, size);
    }
#endif
}

int main(int argc, char **argv) {
    struct hpack *hp;
    int tbl_sz = 4096;
    uint32_t flags = 0;

    struct priv prv;
    memset(&prv, 0, sizeof prv);

    if(argc > 1) {
        flags = argv[1][0];
        if(flags >= '0' && flags <= '9') {
            flags -= '0';
        } else {
            flags = 0;
        }
        // HPACK_CFG_DEGRADED = 1
        // HPACK_CFG_SEND_PTR = 2
        // HPACK_CFG_SEND_ERR = 4
    }

    char buf[65536];
    const char *name, *value;
    struct hpack_decoding dec;
    memset(&dec, 0, sizeof dec);

    dec.blk         = hblock;
    dec.blk_len     = sizeof(hblock);
    dec.buf         = buf;
    dec.buf_len     = sizeof(buf);
    dec.cb          = callback;
    dec.priv        = &prv;
    dec.cut         = 0;


    int rc = 1;
    while(rc > 0) {

        dprintf("START %p[+%d]=0x%02x\n",
                dec.blk,
                (char *)dec.blk - hblock,
                *(char *)dec.blk);

        hp = hpack_decoder(tbl_sz, -1, hpack_default_alloc, flags);

        rc = hpack_decode(hp, &dec);
        if(rc != 0 && (rc == HPACK_RES_IDX || prv.errptr != NULL)) {
            printf("ERROR %d: %s\n", rc, hpack_strerror(rc));
            if(prv.errptr != NULL) {
                dec.blk_len -= (prv.errptr - hblock);
                dec.blk = prv.errptr;
                rc = 1;
                prv.errptr = NULL;
            }
            dprintf("\nERROR restart=%p[+%d]=0x%02x\n\n",
                    dec.blk,
                    (char *)dec.blk - hblock,
                    *(char *)dec.blk
                    );
        }
        hpack_free(&hp);
    }

    if(rc) {
        printf("rc=%d %s\n\n\n", rc, hpack_strerror(rc));
    }
    
    printf("Headers:\n");
    for(int i=0; i<hindex; ++i) {
        printf("%s: %s\n", headers[i].name, headers[i].value);
    }
    
    return 0;
}
