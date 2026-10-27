/* -*- P4_16 -*- */

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

/*Custom header for recirculation*/
header recirc_h {
    bit<8>       minRow;
    bit<16>  current_time_window;
    bit<16>       persistance_count;
    bit<8>        is_recirc;
    bit<16>       min_last_l_current_time_window;

}

/* IPV4 header */
header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;

}

/* TCP header */
header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
    /* Recirculation */
    // bit<16> is_recirc;
}

/* UDP header */
header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
    /* Recirculation */
    // bit<16> is_recirc;

}


/***********************  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
    recirc_h     recirc;

}


/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {

    bit<32> current_item_ID;
    bit<32> current_item_src_ID;
    bit<32> current_item_dst_ID;
    bit<32> reg_item_src_ID;
    bit<32> reg_item_dst_ID;
    bit<(INDEX_WIDTH)> hash1;
    bit<32> hash_id;
    bit<32> reg_item_ID;
    bit<16> persistance_count;
    bit<16> current_window;
    bit<16> last_window;
    // Random value generated for probabilistic replacement
    bit<16> random_value;

    // Helper variables
    bit<1> process_sketch;
    bit<16> persistance_count_incr;
    bit<1> is_first;
    bit<1> is_block;
    bit<1> prob_replacement;
    bit<16> divided_value;
    bit<16> one_over_persistance;
    bit<8> difference_bit;
    bit<1> is_forced;
    bit<32> pkt_count;
    bit<16> hdr_srcport;
    bit<16> hdr_dstport;
    bit<8> proto;
    bit<16> last_l_current_time_window;

    bit<1> set_val;

    // 2ROW
    bit<1> is_hash2;
    bit<1> minRow;
    bit<(INDEX_WIDTH)> hash2;
    bit<32> reg_item_ID_snd;
    bit<16> persistance_count_snd;
    bit<16> persistance_count_fst;
    bit<16> min_persistance_count;
    bit<16> last_window_snd;
    bit<16> last_l_current_time_window_snd;
    bit<16> min_last_l_current_time_window;
    bit<16> current_window_temp;

}

struct flow_class_digest {  // maximum size allowed is 47 bytes

    ipv4_addr_t  source_addr;   // 32 bits
    ipv4_addr_t  destin_addr;   // 32 bits
    bit<32> pkt_count;
    bit<8> minRow;
}
