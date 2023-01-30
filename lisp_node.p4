#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

/*************************************************************************
***********************  C O N S T A N T S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTOCOL_UDP = 0x11; //ipv4 protocol 17: udp
const bit<8>  PROTOCOL_TCP = 0x6;
const bit<16> LISP_TUNNEL_PORT = 4341; // udp dest port is for lisp ipv4 encapsulation 4341
const bit<16> LISP_HEADER_LENGTH = 0x8; // Lisp header length is 64 bit or 8 byte
const bit<16> UDP_HEADER_LENGTH = 0x8; // udp header length is 64 bit or 8 byte
const bit<16> UDP_PLUS_LISP_HEADER_LENGTH = 0x10; // combinded lisp+udp header length (16 byte)
const bit<16> UDP_PLUS_LISP_PLUS_HEADER_LENGTH = 0x24; // combinded lisp+udp+ipv4 header length (16+20 byte)

const bit<16> UDP_SRC_PORT_MAX = 65535;
const bit<2> UDP_SRC_PORT = 0x1;
const bit<2> UDP_DST_PORT = 0x2;
#define UDP_SRC_PORT_MAX_BIT_LENGTH 16

const bit<48> ONE_SECOND = 0x100000;
const bit<32> MAP_REQUEST_ENTRIES = 0x1000;

#define P4RUNTIME_CONTROLLER_PORT 1
#define MAP_REGISTER_ENTRIES 1024
#define EID_LENGTH 32
#define TIMESTAMP_LENGTH 48
const PortId_t CPU_PORT = 192;



typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


struct ingress_metadata_t {
    int<8> rnd_load_balance_group;
    bit<16> flow_src_port;
    bit<16> flow_dst_port;
    bit<2> nat_udp_port_type;
    bit<16> nat_udp_port;
}

// Packet-in header. Prepended to packets sent to the CPU_PORT and used by the
// P4Runtime server (Stratum) to populate the PacketIn message metadata fields.
// Here we use it to carry the original ingress port where the packet was
// received.
header cpu_in_header_t {
    PortId_t  ingress_port;
    bit<7>      padding;
}

// Packet-out header. Prepended to packets received from the CPU_PORT. Fields of
// this header are populated by the P4Runtime server based on the P4Runtime
// PacketOut metadata fields. Here we use it to inform the P4 pipeline on which
// port this packet-out should be transmitted.
header cpu_out_header_t {
    PortId_t  egress_port;
    bit<1>    already_recirculated; // removed from padding
    bit<6>    padding;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> totalLen;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


// ---------  LISP header is depending on flags for different header fields  --------- 
//                  --> split header depending on flags

header lisp_flags_t {
    bit<1> N;
    bit<1> L;
    bit<1> E;
    bit<1> V;
    bit<1> I;
    bit<3> flags;
}

header lisp_nonce_t {
    bit<24> nonce;
}

header lisp_map_t {
    bit<12> source_map;
    bit<12> dst_map;
}

header lisp_locator_t {
    bit<32> locator_status;
}

header lisp_instance_t {
    bit<24> instance_id;
    bit<8> lsb;
}



struct egress_metadata_t {}


struct metadata_t {
    @name("ingress_metadata")
    ingress_metadata_t ingress_metadata;
    egress_metadata_t egress_metadata;
    egress_intrinsic_metadata_t egress_intrinsic_metadata;
    ingress_intrinsic_metadata_t ingress_intrinsic_metadata;
}

struct header_t {
    cpu_out_header_t cpu_out;
    cpu_in_header_t cpu_in;
    @name("ethernet")
    ethernet_t ethernet;
    @name("ipv4")
    ipv4_t ipv4;
    @name("udp")
    udp_t udp;
    //lisp header parts
    lisp_flags_t lisp_flags;
    lisp_nonce_t lisp_nonce;
    lisp_map_t lisp_map;
    lisp_locator_t lisp_locator;
    lisp_instance_t lisp_instance;
    @name("inner lisp header ipv4")
    ipv4_t inner_header;
    @name("udp_after_encapsulation")
    udp_t udp_after_encapsulation;

    //second encapsulation header
    
    //lisp header parts
    lisp_flags_t lisp_flags_on_arrival;
    lisp_nonce_t lisp_nonce_on_arrival;
    lisp_map_t lisp_map_on_arrival;
    lisp_locator_t lisp_locator_on_arrival;
    lisp_instance_t lisp_instance_on_arrival;
    @name("inner lisp header ipv4")
    ipv4_t inner_header_on_arrival;
    @name("udp_after_encapsulated_on_arrival")
    udp_t udp_after_encapsulated_on_arrival;



    @name("tcp")
    tcp_t tcp;

}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// ---------------------------------------------------------------------------
// Ingress Parser
// ---------------------------------------------------------------------------

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition accept;
    }
}

parser SwitchIngressParser(
        packet_in packet, 
        out header_t hdr, 
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(packet, ig_intr_md);
        transition select(ig_intr_md.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.cpu_out);
        transition parse_ethernet;
    }


    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        //transition select based on ipv4 protocol
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_TCP: parse_tcp;
            PROTOCOL_UDP: parse_udp; //lisp ipv4 encapsulation uses udp
            default: accept;
        }
    }

    /*
        Parse TCP or UDP header
    */

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            LISP_TUNNEL_PORT: parse_lisp_flags; //for lisp encapsulation UDP dst port is 4341
            default: accept;
        }
    }

    state parse_udp_stop {
        packet.extract(hdr.udp_after_encapsulated_on_arrival);
        transition accept;
    }

    /* 
        Parse LISP header depending on set flags
    */

    state parse_lisp_flags {
        packet.extract(hdr.lisp_flags_on_arrival);
        transition select(hdr.lisp_flags_on_arrival.N) {
            1: parse_lisp_nonce; 
            default: parse_lisp_map;
        }
    }

    state parse_lisp_nonce {
        packet.extract(hdr.lisp_nonce_on_arrival);
        transition select(hdr.lisp_flags_on_arrival.L) {
            1: parse_lisp_locator; 
            default: parse_lisp_instance;
        }
    }

    state parse_lisp_map {
        packet.extract(hdr.lisp_map_on_arrival);
        transition select(hdr.lisp_flags_on_arrival.L) {
            1: parse_lisp_locator; 
            default: parse_lisp_instance;
        }
    }

    state parse_lisp_locator {
        packet.extract(hdr.lisp_locator_on_arrival);
        transition parse_inner_header;
    }

    state parse_lisp_instance {
        packet.extract(hdr.lisp_instance_on_arrival);
        transition parse_inner_header;
    }

    /*
        Parse inner ipv4 header if packet was encapsulated
    */

    state parse_inner_header {
        packet.extract(hdr.inner_header_on_arrival);
        transition select(hdr.inner_header_on_arrival.protocol) {
            PROTOCOL_TCP: parse_tcp;
            PROTOCOL_UDP: parse_udp_stop;
            default: accept;
        }
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout header_t hdr, inout metadata_t ig_md) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(
        inout header_t hdr, 
        inout ingress_metadata_t ig_md, 
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
    
    Register<bit<32>, bit<10>>(MAP_REQUEST_ENTRIES) eids_with_map_request;

    bool bool_for_testing = false;

    bit<10> reg_map_request_index = 0;
    bit<EID_LENGTH> reg_eid = 0;

    Random<bit<24>>() rnd_generator;
    bit<24> random_nonce = rnd_generator.get();

    //To decide in which group this packet should go in load balancing scenario for multi homing, 
    //reuse first 7 bits of random nonce (used as key in range match of ipv4_lpm)
    bit<8> random_lb_from_nonce = 0;    // use a 8 bit variable, so you can add a zero as highest bit to 7bit random value (always positive)
    int<8> random_ipv4_index_for_group_association = 0; // helps for python p4runtime (problem with negative integers with less bits then a normal int) [I guess]

    Hash<bit<UDP_SRC_PORT_MAX_BIT_LENGTH>>(HashAlgorithm_t.CRC16) udp_port_hash;
    Hash<bit<10>>(HashAlgorithm_t.CRC16) hash_register_index;
    Hash<bit<10>>(HashAlgorithm_t.CRC16) hash_register_index_inner_header;


    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action pick_up(){
        ig_intr_dprsr_md.drop_ctl = 0x0; // Don't drop packet.
    }

    //send packet to local controller
    action send_packet_to_local_controller() {
        ig_intr_tm_md.ucast_egress_port = CPU_PORT;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    
    action decapsulate_packet() {
        
        // Replace all header fields with tunnel header
        hdr.ipv4.version = hdr.inner_header_on_arrival.version;
        hdr.ipv4.ihl = hdr.inner_header_on_arrival.ihl;
        // DSCP and ECN (congestion notification) should be copied to inner header --> unchanged
        hdr.ipv4.ecn = hdr.inner_header_on_arrival.ecn;
        hdr.ipv4.totalLen = hdr.inner_header_on_arrival.totalLen;
        hdr.ipv4.identification = hdr.inner_header_on_arrival.identification;
        hdr.ipv4.flags = hdr.inner_header_on_arrival.flags;
        hdr.ipv4.fragOffset = hdr.inner_header_on_arrival.fragOffset;
        // Only replace outer ttl with inner ttl if outer ttl is bigger
        if(hdr.ipv4.ttl > hdr.inner_header_on_arrival.ttl){//suppression of looping
            hdr.ipv4.ttl = hdr.inner_header_on_arrival.ttl;
        }
        hdr.ipv4.protocol = hdr.inner_header_on_arrival.protocol;
        hdr.ipv4.hdrChecksum = hdr.inner_header_on_arrival.hdrChecksum;
		hdr.ipv4.srcAddr = hdr.inner_header_on_arrival.srcAddr;
		hdr.ipv4.dstAddr = hdr.inner_header_on_arrival.dstAddr;

        
        hdr.inner_header_on_arrival.setInvalid();
        hdr.lisp_flags_on_arrival.setInvalid();
        hdr.lisp_nonce_on_arrival.setInvalid();
        hdr.lisp_map_on_arrival.setInvalid();
        hdr.lisp_locator_on_arrival.setInvalid();
        hdr.lisp_instance_on_arrival.setInvalid();
        hdr.udp.setInvalid();

    }

    table decapsulate_lpm {
        actions = {
            decapsulate_packet;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 128;
        default_action = NoAction();
    }

    

    table allowed_prefixes_lpm {
        actions = {
            drop;
            NoAction;
        }
        key = {
            hdr.ipv4.srcAddr: lpm;
            ig_intr_md.ingress_port: exact;
        }
        size = 128;
        default_action = drop();
    }

    table valid_lisp_destinations_lpm {
        actions = {
            drop;
            pick_up;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 128;
        default_action = drop();
    }


    action encapsulate_packet(ip4Addr_t switch_src, ip4Addr_t switch_dst, bit<8> udp_port_type, bit<16> udp_port) {

        /*
            Get hash value as udp source port for encapsulation
        */

        bit<16> udp_src_port;
        

        // Use 5-tuple hash for UDP, TCP (theoretically Stream Control Transmission Protocol (SCTP) too)
        // If it's neither, use only ipv4 src and dst
        udp_src_port = udp_port_hash.get(
	        { hdr.ipv4.srcAddr,
	          hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              ig_md.flow_src_port,
              ig_md.flow_dst_port });

        /*
            Set udp header values for ipv4-ipv4 encapsulation
        */

        hdr.udp_after_encapsulation = hdr.udp;
        
        hdr.udp.setValid();
        hdr.udp.srcPort = udp_src_port;
        hdr.udp.dstPort = 4341;
		hdr.udp.totalLen = hdr.ipv4.totalLen + UDP_PLUS_LISP_HEADER_LENGTH;// no inner length (included in original total length) //in byte
		hdr.udp.checksum = 0;


        ig_md.nat_udp_port_type = udp_port_type[1:0];
        ig_md.nat_udp_port = udp_port;


        /*
            Create lisp header
        */

        hdr.lisp_flags.setValid();
        hdr.lisp_flags.N = 0x1;
        hdr.lisp_flags.L = 0x1;
        hdr.lisp_flags.E = 0x0;
        hdr.lisp_flags.V = 0x0;
        hdr.lisp_flags.I = 0x0;
        hdr.lisp_flags.flags = 0x0;
        
        hdr.lisp_nonce.setValid();
        hdr.lisp_nonce.nonce = random_nonce;
        
        hdr.lisp_locator.setValid(); // currently nothing goes on in the second half of the lisp header
        hdr.lisp_locator.locator_status = 0x0;

        /*
            Save original ipv4 header in inner ipv4 header
        */

        hdr.inner_header.setValid();
        hdr.inner_header.version = hdr.ipv4.version;
        hdr.inner_header.ihl = hdr.ipv4.ihl;
        hdr.inner_header.dscp = hdr.ipv4.dscp;
        hdr.inner_header.ecn = hdr.ipv4.ecn;
        hdr.inner_header.totalLen = hdr.ipv4.totalLen;
        hdr.inner_header.identification = hdr.ipv4.identification;
        hdr.inner_header.flags = hdr.ipv4.flags;
        hdr.inner_header.fragOffset = hdr.ipv4.fragOffset;
        hdr.inner_header.ttl = hdr.ipv4.ttl;
        hdr.inner_header.protocol = hdr.ipv4.protocol;
        hdr.inner_header.hdrChecksum = hdr.ipv4.hdrChecksum;
		hdr.inner_header.srcAddr = hdr.ipv4.srcAddr;
		hdr.inner_header.dstAddr = hdr.ipv4.dstAddr;

        /*
            Update outer header
        */

        hdr.ipv4.version = 4; 
        hdr.ipv4.ihl = 0x5; // 5*32 bit (min length) or 5*4 byte
        // DSCP and ECN (congestion notification) should be copied from inner header --> unchanged

        // new headers added to length
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + UDP_PLUS_LISP_PLUS_HEADER_LENGTH;

        //hdr.ipv4.identification = 0; //Not sure with this one

        hdr.ipv4.flags = 2; // don't fragment (df) -- Packets should be splitted?

        hdr.ipv4.fragOffset = 0;

        // TTL should be copied from inner header --> unchanged
        hdr.ipv4.protocol = PROTOCOL_UDP; //change protocol to udp (encapsulation uses udp)
        // New Checksum calculated at the bottom
        hdr.ipv4.srcAddr = switch_src;
		hdr.ipv4.dstAddr = switch_dst;
        
    }

    table encapsulate_lpm {
        actions = {
            encapsulate_packet;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
            ig_md.rnd_load_balance_group: range;
        }
        size = 4500;
        default_action = NoAction();
    }



    action replace_destination(ip4Addr_t new_destination) {
        hdr.ipv4.dstAddr = new_destination;
    }

    table replace_destination_address_exact {
        actions = {
            replace_destination;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        size = 512;
        default_action = NoAction();
    }

    action replace_source_address(ip4Addr_t new_source) {
        hdr.ipv4.srcAddr = new_source;
    }

    table replace_source_address_exact {
        actions = {
            replace_source_address;
            NoAction;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        size = 512;
        default_action = NoAction();
    }



    action set_outgoing_port(bit<9> port) {
        //meta.egress_intrinsic_metadata.egress_port = port;
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Change port so packet (if send) goes to local controller
    action map_request() {
        send_packet_to_local_controller();
    }

    action forward_natively(bit<9> port) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    
    table ipv4_lpm {
        actions = {
            drop;
            map_request;
            set_outgoing_port;
            forward_natively;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 24000;
        default_action = map_request(); // If no known ipv4 destination --> trigger map request
    }



    action set_smac_dmac(bit<48> smac, bit<48> dmac) {
        hdr.ethernet.srcAddr = smac;
        hdr.ethernet.dstAddr = dmac;
    }

    action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    table forward {
        actions = {
            set_dmac;
            set_smac_dmac;
            drop;
            NoAction;
        }
        key = {
            ig_intr_tm_md.ucast_egress_port: exact;
        }
        size = 256;
        default_action = NoAction();
    }


    apply {

        if(hdr.ipv4.isValid()){

            // Calculate index for register use
            // Use the inner header destination eid for an encapsulated packet and the outer/single ipv4 header destination for a normal packet
            if(hdr.inner_header_on_arrival.isValid()){
                reg_map_request_index = hash_register_index_inner_header.get({ hdr.inner_header_on_arrival.dstAddr });
            }
            else{
                reg_map_request_index = hash_register_index.get({ hdr.ipv4.dstAddr });
            }
            
            random_lb_from_nonce[6:0] = random_nonce[6:0];  // Add a 0 as highest bit to random number -> only positive values
            random_ipv4_index_for_group_association = (int<8>) random_lb_from_nonce;  // helps for python p4runtime (problem with negative integers with less bits then a normal int) [I guess]

            // Set random number as load balance group (used in encapsulation as key to determine which rloc for eid should be used)
            ig_md.rnd_load_balance_group = random_ipv4_index_for_group_association;

            ig_md.flow_src_port = 0;
            ig_md.flow_dst_port = 0;
            ig_md.nat_udp_port_type = 0; // initialize udp port type for encapsulation with zero (represents normal xtr)

            
            // Reset register value via control plane
            if (hdr.cpu_out.isValid()) {
                // If we are in the correct pipeline, overwrite register entry
                if(hdr.cpu_out.already_recirculated == 1){  //ig_intr_md.ingress_port == hdr.cpu_out.egress_port){
                    eids_with_map_request.write(reg_map_request_index, 0);
                    drop();
                }
                // Else forward packet to loopback port for correct pipeline
                // Necessary because registers are not synchronized between pipelines
                else{
                    hdr.cpu_out.already_recirculated = 1;
                    ig_intr_tm_md.ucast_egress_port = hdr.cpu_out.egress_port;
                }
            }

            else{

                // Check if incoming traffic is encapsulated and decapsulated it if necessary
                decapsulate_lpm.apply();

                // If packet came from inside the lisp site (distinction using the ingress port):

                // Drop packet if it came from inside but isn't part of the allowed prefix for lisp site
                allowed_prefixes_lpm.apply();

                // Drop packet if the destination can't be a lisp eid
                valid_lisp_destinations_lpm.apply();

                

                
                if(hdr.udp.isValid()){
                    ig_md.flow_src_port = hdr.udp.srcPort;
                    ig_md.flow_dst_port = hdr.udp.dstPort;
                }
                else if(hdr.tcp.isValid()){
                    ig_md.flow_src_port = hdr.tcp.srcPort;
                    ig_md.flow_dst_port = hdr.tcp.dstPort;
                }

                // Check if packet has to be encapsulated
                encapsulate_lpm.apply();
                    
                // A xTR behind a NAT uses a static random udp src port, so the NAT translates it to a specific one (which the RTR nows)
                if(ig_md.nat_udp_port_type == UDP_SRC_PORT){
                    hdr.udp.srcPort = ig_md.nat_udp_port; // overwrite the random chosen udp src port
                }
                    
                // A RTR uses 4342 as udp src port for encapsulation and a specific udp dst port which gets translated by the NAT before the xTR
                else if(ig_md.nat_udp_port_type == UDP_DST_PORT){
                    hdr.udp.srcPort = 4342;
                    hdr.udp.dstPort = ig_md.nat_udp_port;
                }

                // LISP-NAT
                replace_source_address_exact.apply();
                replace_destination_address_exact.apply();


                //if(!ipv4_lpm.apply().hit){
                switch (ipv4_lpm.apply().action_run) {
                    // If destination is unknown:
                    map_request: {
                        // Get the corresponding Register Entry and check, if it was already sent to the controller for a Map-Request
                        reg_eid = eids_with_map_request.read(reg_map_request_index);
                        // Write the unknown destination in the register (either it is the same [packet gets dropped])
                        // or it is a new one which would have overwritten the old entry
                        eids_with_map_request.write(reg_map_request_index, hdr.ipv4.dstAddr);
                    
                        if (reg_eid == hdr.ipv4.dstAddr){
                            drop();
                        }
                      }
                }

                forward.apply();

                if (ig_intr_tm_md.ucast_egress_port == CPU_PORT) {        
                    hdr.cpu_in.setValid();
                    hdr.cpu_in.ingress_port = ig_intr_md.ingress_port;
                    exit;
                }

                
            }
        }
    }
}


/*************************************************************************
**************  I N G R E S S   D E P A R S E R  *******************
*************************************************************************/

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {

        hdr.ipv4.hdrChecksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.dscp,
                 hdr.ipv4.ecn,
                 hdr.ipv4.totalLen,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.fragOffset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.srcAddr,
                 hdr.ipv4.dstAddr});


        if(hdr.inner_header.isValid()){
            hdr.inner_header.hdrChecksum = ipv4_checksum.update(
                {hdr.inner_header.version,
                 hdr.inner_header.ihl,
                 hdr.inner_header.dscp,
                 hdr.inner_header.ecn,
                 hdr.inner_header.totalLen,
                 hdr.inner_header.identification,
                 hdr.inner_header.flags,
                 hdr.inner_header.fragOffset,
                 hdr.inner_header.ttl,
                 hdr.inner_header.protocol,
                 hdr.inner_header.srcAddr,
                 hdr.inner_header.dstAddr});
        }


        if(hdr.inner_header_on_arrival.isValid()){
            hdr.inner_header_on_arrival.hdrChecksum = ipv4_checksum.update(
                {hdr.inner_header_on_arrival.version,
                 hdr.inner_header_on_arrival.ihl,
                 hdr.inner_header_on_arrival.dscp,
                 hdr.inner_header_on_arrival.ecn,
                 hdr.inner_header_on_arrival.totalLen,
                 hdr.inner_header_on_arrival.identification,
                 hdr.inner_header_on_arrival.flags,
                 hdr.inner_header_on_arrival.fragOffset,
                 hdr.inner_header_on_arrival.ttl,
                 hdr.inner_header_on_arrival.protocol,
                 hdr.inner_header_on_arrival.srcAddr,
                 hdr.inner_header_on_arrival.dstAddr});
        }

        
        pkt.emit(hdr);
    }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

// Empty egress parser/control blocks
parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;
    
    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition accept;
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}



/*************************************************************************
***********************  E G R E S S  D E P A R S E R  *******************************
*************************************************************************/


control SwitchEgressDeparser(packet_out packet, inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {

    apply {
        packet.emit(hdr.cpu_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.lisp_flags);
        packet.emit(hdr.lisp_nonce);
        packet.emit(hdr.lisp_map);
        packet.emit(hdr.lisp_locator);
        packet.emit(hdr.lisp_instance);
        packet.emit(hdr.inner_header);
        packet.emit(hdr.udp_after_encapsulation);
        packet.emit(hdr.lisp_flags_on_arrival);
        packet.emit(hdr.lisp_nonce_on_arrival);
        packet.emit(hdr.lisp_map_on_arrival);
        packet.emit(hdr.lisp_locator_on_arrival);
        packet.emit(hdr.lisp_instance_on_arrival);
        packet.emit(hdr.inner_header_on_arrival);
        packet.emit(hdr.udp_after_encapsulated_on_arrival);
        packet.emit(hdr.tcp);
        
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;