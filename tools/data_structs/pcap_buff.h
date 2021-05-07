#include <chaste/types/types.h>
#include "../../src/data_structs/expcap.h"
#include "../../src/data_structs/pcap-structures.h"
#include "buff.h"

typedef struct {
    pcap_pkthdr_t* hdr; // header
    char* pkt;          // packet data
    expcap_pktftr_t* ftr; // footer
    uint64_t idx;       // index
    int64_t snaplen;
    int64_t max_filesize;
    bool usec;
    bool expcap;
    buff_t* _buff; // _private buff_t.
} pcap_buff_t;

typedef enum {
    PKT_OK = 0,
    PKT_PADDING,
    PKT_RUNT,
    PKT_ERROR,
    PKT_EOF,
    PKT_OVER_SNAPLEN,
    PKT_SNAPPED
} pkt_info_t;

/* Initialize a packet buffer for writing. */
buff_error_t pcap_buff_init(char* filename, int64_t snaplen, int64_t max_filesize, bool usec,
                           bool conserve_fds, bool allow_duplicates, pcap_buff_t* pcap_buffo);

/* Read in a pcap from disk. */
/* The underlying buff is read only */
buff_error_t pcap_buff_from_file(pcap_buff_t* pcap_buff, char* filename, bool is_expcap);

/* Return information about the current packet */
pkt_info_t pcap_buff_get_info(pcap_buff_t* pcap_buff);

/* Adjust hdr, data, idx, ftr to point to the next packet and return packet information */
pkt_info_t pcap_buff_next_packet(pcap_buff_t* pcap_buff);

/* Get the filename used by the buff_t. */
char* pcap_buff_get_filename(pcap_buff_t* pcap_buff);

/* Write a full packet (headers + data + footer). Footer can be NULL if not used. */
/* Header caplen will be adjusted to account for the presence of a footer.. */
buff_error_t pcap_buff_write(pcap_buff_t* pcap_buff, pcap_pkthdr_t* hdr, char* data, size_t data_len, expcap_pktftr_t* ftr);

/* Flushes _buff to disk. */
buff_error_t pcap_buff_flush_to_disk(pcap_buff_t* pcap_buff);

/* Check if _buff is at eof. */
bool pcap_buff_eof(pcap_buff_t* pcap_buff);

/* Close and release resources associated with this pcap_buff */
buff_error_t pcap_buff_close(pcap_buff_t* pcap_buff);

/* Translate an info value to a string */
const char* pcap_buff_strinfo(pkt_info_t info);
