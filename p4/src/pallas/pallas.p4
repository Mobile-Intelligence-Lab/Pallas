/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "./include/types.p4"
#include "./include/headers.p4"
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.process_sketch = 1;
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            TYPE_RECIRC: parse_recirc;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_recirc {
       pkt.extract(hdr.recirc);
       transition accept;
    }



}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
/***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* Forward to a specific port upon classification */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    /* Custom Do Nothing Action */
    action nop(){}

    /* Registers */
    /* ------------------------------------------------------------------------ */
    // FIRST HASH and SECOND HASH:

    // ITEM KEY (K_ij)
    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_item_ID;
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_item_ID)
    read_update_item_ID = {
        void apply(inout bit<32> item_ID, out bit<32> output) {
            output = item_ID;
            if(item_ID == 0){
                item_ID = meta.hash_id;
            }
            else {
                if (meta.is_forced == 1){
                    item_ID = meta.hash_id;
                }
            }
        }
    };
    // second
    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_item_ID_snd;
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_item_ID_snd)
    read_update_item_ID_snd = {
        void apply(inout bit<32> item_ID, out bit<32> output) {
            output = item_ID;
            if(item_ID == 0){
                item_ID = meta.hash_id;
            }
            else {
                if (meta.is_forced == 1){
                    item_ID = meta.hash_id;
                }
            }
        }
    };

    // PERSISTENCE VALUE (P_ij)
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_persistance_count;
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_persistance_count)
    read_update_persistance_count = {
        void apply(inout bit<16> persistance_count, out bit<16> output) {
            if (meta.is_first == 1){
                persistance_count =  1;
            }
            else{
                if (meta.last_l_current_time_window == 2){
                    persistance_count = persistance_count + 1;
                }
            }
            output = persistance_count;
        }
    };
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_persistance_count)
    read_only_persistance_count = {
        void apply(inout bit<16> persistance_count, out bit<16> output) {
            output = persistance_count;
        }
    };
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_persistance_count)
    decay_persistance_count = {
        void apply(inout bit<16> persistance_count, out bit<16> output) {
            // if (meta.persistance_count != 1){
            persistance_count = persistance_count - 1;
            // }
            output = persistance_count;
        }
    };
    // second
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_persistance_count_snd;
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_persistance_count_snd)
    read_update_persistance_count_snd = {
        void apply(inout bit<16> persistance_count, out bit<16> output) {
            if (meta.is_first == 1){
                persistance_count =  1;
            }
            else{
                if (meta.last_l_current_time_window_snd == 2){
                    persistance_count = persistance_count + 1;
                }
            }
            output = persistance_count;
        }
    };
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_persistance_count_snd)
    read_only_persistance_count_snd = {
        void apply(inout bit<16> persistance_count, out bit<16> output) {
            output = persistance_count;
        }
    };
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_persistance_count_snd)
    decay_persistance_count_snd = {
        void apply(inout bit<16> persistance_count, out bit<16> output) {
            // if (meta.persistance_count != 1){
            persistance_count = persistance_count - 1;
            // }
            output = persistance_count;
        }
    };

    // LAST TIME WINDOW
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_last_time_window;
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_last_time_window)
    update_last_time_window = {
        void apply(inout bit<16> last_time_window, out bit<16> output) {
            // if (meta.is_first == 1){
            //     last_time_window = meta.current_window;
            // }
            // else {
            if (last_time_window < meta.current_window){
                last_time_window = meta.current_window;
                output = (bit<16>)2;
            }
            else {
                output = (bit<16>)1;
            }
            // }
        }
    };
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_last_time_window)
    update_last_time_window_first = {
        void apply(inout bit<16> last_time_window) {
            // if (hdr.recirc.min_last_l_current_time_window == 2){
            last_time_window = meta.current_window;
            // }
        }
    };
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_last_time_window)
    read_last_time_window = {
        void apply(inout bit<16> last_time_window, out bit<16> output) {
            if (last_time_window >= meta.current_window){
                output = (bit<16>)1;
            }
            else {
                output = (bit<16>)2;
            }
        }
    };
    // second
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_last_time_window_snd;
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_last_time_window_snd)
    update_last_time_window_snd = {
        void apply(inout bit<16> last_time_window, out bit<16> output) {
            // if (meta.is_first == 1){
            //     last_time_window = meta.current_window;
            // }
            // else {
            if (last_time_window < meta.current_window){
                last_time_window = meta.current_window;
                output = (bit<16>)2;
            }
            else {
                output = (bit<16>)1;
            }
            // }
        }
    };
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_last_time_window_snd)
    update_last_time_window_first_snd = {
        void apply(inout bit<16> last_time_window) {
            last_time_window = meta.current_window;
        }
    };
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_last_time_window_snd)
    read_last_time_window_snd = {
        void apply(inout bit<16> last_time_window, out bit<16> output) {
            if (last_time_window >= meta.current_window){
                output = (bit<16>)1;
            }
            else {
                output = (bit<16>)2;
            }
        }
    };

    /* -- */
    /* Define Register for packet count */
    Register<bit<32>,bit<1>>(1) reg_pkt_count;
    RegisterAction<bit<32>,bit<1>,bit<32>>(reg_pkt_count)
    read_count_packet = {
        void apply(inout bit<32> pkt_count, out bit<32> output) {
            // if (pkt_count == 19600){ //caida2019
            // if (pkt_count == 22293){ //caida2018 - 1000
            // if (pkt_count == 11146){ //caida2018 - 2000
            if (pkt_count == 14862){ //caida2018 - 1500
            // if (pkt_count == 12800){    //caida2016
            // if (pkt_count == 14550){    //caida2016-all
                pkt_count = 0;
            }
            else {
                pkt_count = pkt_count + 1;
            }
            output = pkt_count;
        }
    };
    RegisterAction<bit<32>,bit<1>,bit<32>>(reg_pkt_count)
    read_only_count_packet = {
        void apply(inout bit<32> pkt_count, out bit<32> output) {
            output = pkt_count;
        }
    };

    /* Define Register for current time window count */
    Register<bit<16>,bit<1>>(1) reg_current_time_window;
    RegisterAction<bit<16>,bit<1>,bit<16>>(reg_current_time_window)
    update_current_time_window = {
        void apply(inout bit<16> time_window, out bit<16> output) {
            time_window = time_window + 1;
            output = time_window;
        }
    };
    RegisterAction<bit<16>,bit<1>,bit<16>>(reg_current_time_window)
    read_current_time_window = {
        void apply(inout bit<16> time_window, out bit<16> output) {
            output = time_window;
        }
    };

    /* Define Register for last time window count */
    // Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_last_time_window;
    // RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_last_time_window)
    // update_last_time_window = {
    //     void apply(inout bit<16> last_time_window, out bit<16> output) {
    //         output = last_time_window;
    //         // if (meta.is_first == 1){
    //         //     last_time_window = meta.current_window;
    //         // }
    //         // else {
    //         if (last_time_window < meta.current_window){
    //             last_time_window = meta.current_window;
    //         }
    //         // }
    //     }
    // };

    /* Define Register for recirculation count */
    Register<bit<32>,bit<1>>(1) reg_count_recirc;
    RegisterAction<bit<32>,bit<1>,bit<32>>(reg_count_recirc)
    read_count_recirc = {
        void apply(inout bit<32> count_recirc, out bit<32> output) {
            count_recirc = count_recirc + 1;
        }
    };

    /* ------------------------------------------------------------------------ */

    /* Declaration of the hashes*/
    // TODO: Update accordingly
    Hash<bit<32>>(HashAlgorithm_t.CRC64)              item_id_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)   idx1_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC32)   idx2_calc;

    /* Flow identity in this prototype uses the source/destination IPv4 pair. */
    action get_item_src_ID() {
        // meta.item_ID = item_id_calc.get({hdr.ipv4.src_addr,
        //     hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
        meta.current_item_src_ID = hdr.ipv4.src_addr;
    }
    action get_item_dst_ID() {
        // meta.item_ID = item_id_calc.get({hdr.ipv4.src_addr,
        //     hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
        meta.current_item_dst_ID = hdr.ipv4.dst_addr;
    }
    /* Calculate hash of the 2-tuple to use as 1st register index */
    action get_hash1() {
        meta.hash1 = idx1_calc.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
    }
    action get_hash2() {
        meta.hash2 = idx2_calc.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
    }
    action get_hash_id() {
        meta.hash_id = item_id_calc.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
    }

     /* ------------------------------------------------------------------------ */

    /* Generate an 11-bit random value (0..2047). */
    Random<bit<11>>() random_gen;

     /* ------------------------------------------------------------------------ */

    /* Recirculate packet via loopback port 68 */
    action recirculate(bit<7> recirc_port) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recirc_port;
        hdr.recirc.setValid();
        // hdr.recirc.minRow = (bit<8>)meta.minRow;
        // hdr.recirc.minRow = 0;
        hdr.recirc.persistance_count = meta.min_persistance_count;
        hdr.recirc.min_last_l_current_time_window = meta.min_last_l_current_time_window;
        hdr.recirc.current_time_window = meta.current_window;
        // hdr.recirc.hash1 = (bit<16>)meta.hash1;
        // hdr.recirc.hash2 = (bit<16>)meta.hash2;
        // hdr.recirc.hash_id = meta.hash_id;
        hdr.ipv4.protocol = TYPE_RECIRC;
    }

    action set_division_action(bit<16> f_action){
        meta.one_over_persistance = f_action;
    }
    action set_default_division_action(){
        meta.one_over_persistance = 1;
    }
    action set_min_values(){
        meta.min_last_l_current_time_window = meta.last_l_current_time_window_snd;
        meta.minRow = 1;
        // hdr.recirc.minRow = 1;
        meta.min_persistance_count = meta.persistance_count_snd;
    }

    /* DIVISION TABLE */
    table division_table {
        key = {
            meta.divided_value: exact;
        }
        actions = {set_division_action; @defaultonly set_default_division_action;}
        size = 62100;
        const default_action = set_default_division_action();
    }

    /* Define Helper Actions */

    bit<16> diff_val1_val2;
    bit<16> diff_val1_val2_2;

    action diff_x_y(bit<16> f_value, bit<16> s_value){
        // diff_val1_val2 = (meta.minimum_persistance - meta.persistance_count);
        diff_val1_val2 = (f_value - s_value);
    }
    action diff_x_y_2(bit<16> f_value, bit<16> s_value){
        // diff_val1_val2 = (meta.minimum_persistance - meta.persistance_count);
        diff_val1_val2_2 = (f_value - s_value);
    }

    apply {
        get_hash1();
        get_hash2();
        get_hash_id();
        meta.random_value = (bit<16>)random_gen.get();
        if (hdr.recirc.isValid()){
            meta.is_forced = 1;
            meta.divided_value = hdr.recirc.persistance_count + 1;
            division_table.apply();
            diff_x_y(meta.one_over_persistance, meta.random_value);
            if (hdr.recirc.min_last_l_current_time_window == 2) {
                if(diff_val1_val2[15:15] == 0){
                    if(hdr.recirc.minRow == 0){
                        if (hdr.recirc.persistance_count == 1){      // Replace the ITEM
                            meta.is_first = 1;
                            meta.reg_item_ID  = read_update_item_ID.execute((bit<(INDEX_WIDTH)>)meta.hash1);   // If it is NULL, it stores the current item directly in the register
                            meta.current_window = hdr.recirc.current_time_window;
                            update_last_time_window_first.execute((bit<(INDEX_WIDTH)>)meta.hash1);
                        }
                        else {
                            meta.persistance_count = decay_persistance_count.execute((bit<(INDEX_WIDTH)>)meta.hash1);
                        }
                    }
                    else {
                        meta.current_window = hdr.recirc.current_time_window;
                        if (hdr.recirc.persistance_count == 1){      // Replace the ITEM
                            meta.is_first = 1;
                            meta.reg_item_ID_snd  = read_update_item_ID_snd.execute((bit<(INDEX_WIDTH)>)meta.hash2);   // If it is NULL, it stores the current item directly in the register
                            update_last_time_window_first_snd.execute((bit<(INDEX_WIDTH)>)meta.hash2);
                        }
                        else {
                            meta.persistance_count_snd = decay_persistance_count_snd.execute((bit<(INDEX_WIDTH)>)meta.hash2);
                        }
                    }
                }
            }
            // Invalidate the recirculation header
            hdr.recirc.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;
            // //
            ipv4_forward(292);

        }
        else {
            meta.is_forced = 0;
            meta.prob_replacement = 0;
            meta.is_hash2 = 0;
            if (meta.process_sketch == 1){
                meta.pkt_count = read_count_packet.execute(0);
                if (meta.pkt_count == 0){
                    ig_dprsr_md.digest_type = 1;                                       // Activate the digest to collect the results
                    meta.current_window = update_current_time_window.execute(0);
                }
                else {
                    meta.current_window = read_current_time_window.execute(0);
                }
                // FIRST HASH
                // Case 1: If bucket is empty (first use)
                meta.reg_item_ID  = read_update_item_ID.execute(meta.hash1);          // If it is NULL, it stores the current item directly in the register
                if (meta.reg_item_ID == 0){                                           // If the index is empty, store the current item and do not run the second hash
                    meta.is_first = 1;                                                // It stores the last time window of the item in the register
                    update_last_time_window_first.execute(meta.hash1);
                    meta.persistance_count = read_update_persistance_count.execute(meta.hash1);      // It stores the persistance as 1
                    meta.is_hash2 = 0;
                }
                else if ((meta.reg_item_ID == meta.hash_id)) {                                       // Check if the key in the register entry is the same with the current item key
                    meta.is_first = 0;
                    meta.is_hash2 = 0;
                    meta.last_l_current_time_window = update_last_time_window.execute(meta.hash1);   // Check if the last time window is less than the current window (set last time window as the current if so) (2: if YES)
                    meta.persistance_count = read_update_persistance_count.execute(meta.hash1);      // Increase the persistance by one only if last time window < current time window
                }
                // Case 3: No key match
                else {
                    meta.is_first = 0;
                    meta.is_hash2 = 1;
                    meta.min_last_l_current_time_window = read_last_time_window.execute(meta.hash1);          // Check if the last time window >= current time window (1: If YES)
                    if (meta.min_last_l_current_time_window==2){                                              // If last time window < current window
                        meta.min_persistance_count = read_only_persistance_count.execute(meta.hash1);         // Return the persistance value of the current stored item
                    }
                    else {
                        meta.min_persistance_count = read_only_persistance_count.execute(meta.hash1);         // Return the persistance value of the current stored item
                    }
                }
                // SECOND HASH
                if(meta.is_hash2==1){
                    // Case 1: If bucket is empty (first use)
                    meta.reg_item_ID_snd  = read_update_item_ID_snd.execute(meta.hash2);          // If it is NULL, it stores the current item directly in the register
                    if (meta.reg_item_ID_snd == 0){                                               // If the index is empty, store the current item and do not run the second hash
                        meta.is_first = 1;                               // It stores the last time window of the item in the register
                        update_last_time_window_first_snd.execute(meta.hash2);
                        meta.persistance_count_snd = read_update_persistance_count_snd.execute(meta.hash2);      // It stores the persistance as 1
                        meta.prob_replacement = 0;
                    }
                    else if ((meta.reg_item_ID_snd == meta.hash_id)) {                                           // Check if the key in the register entry is the same with the current item key
                        meta.is_first = 0;
                        meta.prob_replacement = 0;
                        meta.last_l_current_time_window_snd = update_last_time_window_snd.execute(meta.hash2);   // Check if the last time window is less than the current window (set last time window as the current if so) (2: if YES)
                        meta.persistance_count_snd = read_update_persistance_count_snd.execute(meta.hash2);      // Increase the persistance by one only if last time window < current time window
                    }
                    // Case 3: No key match
                    else {
                        meta.is_first = 0;
                        meta.last_l_current_time_window_snd = read_last_time_window_snd.execute(meta.hash2);     // Check if the last time window >= current time window (1: If YES)
                        meta.prob_replacement = 1;
                        meta.persistance_count_snd = read_only_persistance_count_snd.execute(meta.hash2);        // Return the persistance value of the current stored item
                    }
                }

                // PROBABILISTIC REPLACEMENT
                if (meta.prob_replacement == 1){
                    read_count_recirc.execute(0);           // Persistance from first register - persistance from second register
                    meta.minRow = (bit<1>)random_gen.get();
                    if (meta.minRow == 1){                                                    // If the randomly selected row is the second row
                        set_min_values();
                        recirculate(68);
                        hdr.recirc.minRow = 1;
                    }
                    else {
                        recirculate(68);
                        hdr.recirc.minRow = 0;
                    }
                }
                hdr.udp.setInvalid();
                hdr.tcp.setInvalid();
            }
        }

    } //END OF APPLY

} //END OF INGRESS CONTROL

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    // Checksum() ipv4_checksum;
    Digest<flow_class_digest>() digest;
    apply {
        /* we do not update checksum because we used ttl field for stats*/

        if (ig_dprsr_md.digest_type == 1) {

            // digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.divided_value, meta.one_over_persistance, meta.random_value, meta.pkt_count});
            // digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.pkt_count, hdr.recirc.minRow, meta.min_persistance_count, meta.persistance_count_snd});
            // digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.reg_item_src_ID, meta.reg_item_dst_ID, meta.pkt_count, meta.which_block});
            digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.pkt_count, hdr.recirc.minRow});
        }

        // pkt.emit(hdr.ethernet);
        // pkt.emit(hdr.recirc);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.recirc);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
#include "./include/egress.p4"

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
