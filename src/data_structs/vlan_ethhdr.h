typedef struct vlan_ethhdr {
    uint64_t            h_dest : 48;
    uint64_t    	h_source : 48;
    uint16_t		h_vlan_proto;
    uint16_t		h_vlan_TCI;
    uint16_t		h_vlan_encapsulated_proto;
}__attribute__((packed)) vlan_ethhdr_t;
