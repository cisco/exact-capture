/* Pseudo IP header, used in calculating UDP/TCP checksums */
struct pseudo_iphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
} __attribute__((packed));
