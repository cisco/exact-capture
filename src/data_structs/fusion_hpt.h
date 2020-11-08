#include <endian.h>

#define be40toh(x) (be64toh(x) >> 24)

typedef struct fusion_hpt_trailer  {
    uint32_t orig_fcs;
    uint8_t device_id;
    uint8_t port;
    uint64_t seconds_since_epoch : 32;
    uint64_t frac_seconds : 40;
    uint8_t __reserved;
    uint32_t new_fcs;
} __attribute__((packed)) fusion_hpt_trailer_t;
