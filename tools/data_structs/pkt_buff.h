#include <chaste/types/types.h>
#include "../../src/data_structs/expcap.h"
#include "../../src/data_structs/pcap-structures.h"
#include "buff.h"

typedef struct {
    pcap_pkthdr_t* hdr; // header
    char* pkt;          // packet data
    expcap_pktftr_t* ftr; // footer
    uint64_t idx;       // index
    uint64_t snaplen;
    bool usec;
    buff_t* _buff; // _private buff_t.
} pkt_buff_t;

typedef enum {
    PKT_OK = 0,
    PKT_PADDING,
    PKT_RUNT,
    PKT_ERROR,
    PKT_EOF
} pkt_info_t;

/* Initialize a packet buffer for writing. */
buff_error_t pkt_buff_init(char* filename, pkt_buff_t* pkt_buff, int64_t snaplen, int64_t max_filesize, bool usec, bool conserve_fds);

/* Read in a pcap from disk. */
/* The underlying buff is read only */
buff_error_t pkt_buff_from_file(pkt_buff_t*  pkt_buff, char* filename);

/* Adjust hdr, data, idx, ftr to point to the next packet */
pkt_info_t pkt_buff_next_packet(pkt_buff_t* pkt_buff);

/* Get the filename used by the buff_t. */
char* pkt_buff_get_filename(pkt_buff_t* pkt_buff);

/* Write a full packet (headers + data + footer). Footer can be NULL if not used. */
/* Header caplen will be adjusted to account for the presence of a footer.. */
buff_error_t pkt_buff_write(pkt_buff_t* pkt_buff, pcap_pkthdr_t* hdr, char* data, size_t data_len, expcap_pktftr_t* ftr);

/* Flushes _buff to disk. */
buff_error_t pkt_buff_flush_to_disk(pkt_buff_t* pkt_buff);

/* Check if _buff is at eof. */
bool pkt_buff_eof(pkt_buff_t* pkt_buff);
