/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define TYPE_IPV4  0x800
#define UDP_PORT_VXLAN 4789
#define UDP_PROTO 17
#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define VXLAN_HDR_SIZE 8
#define IP_VERSION_4 4
#define IPV4_MIN_IHL 5

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udpLen;
    bit<16> checksum;
}

header vxlan_t {
    bit<16> flags;
    bit<16> gid;
    bit<24> vni;
    bit<8>  reserved;
}


struct metadata {
    bit<24> vxlan_vni;
    bit<32> nexthop;
    bit<32> vtepIP;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t   ipv4;
    udp_t    udp;
    vxlan_t      vxlan;
    ethernet_t   in_ethernet;
    ipv4_t       in_ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: add parser logic */
        transition parse_ethernet;
    }

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_IPV4 : parse_ipv4;
			default : accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            UDP_PROTO : parse_udp;
            default : accept;
        }
	}

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            UDP_PORT_VXLAN : parse_vxlan;
            default : accept;
        }
    }

    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition parse_in_ethernet;
    }

    state parse_in_ethernet {
        packet.extract(hdr.in_ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_in_ipv4;
            default : accept;
        }
    }

    state parse_in_ipv4 {
        packet.extract(hdr.in_ipv4);
        transition accept;
    }


}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control vxlan_ingress_decap(inout headers hdr, inout metadata meta,
                            inout standard_metadata_t standard_metadata) {
    action vxlan_decap() {
        hdr.ethernet.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
        hdr.vxlan.setInvalid();
    }

    table vxlan_decap_lpm {
        key = {
            hdr.in_ipv4.dstAddr : lpm;
        }

        actions = {
            vxlan_decap;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action l2_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table l2_forward_lpm {
        key = {
            hdr.in_ipv4.dstAddr : lpm;
        }

        actions = {
            l2_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (vxlan_decap_lpm.apply().hit) {
                l2_forward_lpm.apply();
            }
        }
    }
}

control vxlan_egress_decap(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply { }
}


control vxlan_ingress_encap(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action set_vni(bit<24> vni) {
        meta.vxlan_vni = vni;
    }

    action set_ipv4_nexthop(bit<32> nexthop) {
        meta.nexthop = nexthop;
    }

    table vxlan_set_vni_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }

        actions = {
            set_vni;
            NoAction;

        }
        size = 1024;
        default_action = NoAction();

    }

    table vxlan_set_nexthop_lpm {

        key = {
            hdr.ipv4.dstAddr : lpm;
        }

        actions = {
            set_ipv4_nexthop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    action set_vtep_ip(bit<32> vtep_ip) {
        meta.vtepIP = vtep_ip;
    }

    table vxlan_set_vtep_ip_lpm {

        key = {
            hdr.ipv4.srcAddr : lpm;
        }

        actions = {
            set_vtep_ip;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action route(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table vxlan_forward_lpm {

        key = {
            meta.nexthop : lpm;
        }

        actions = {
            route;
            NoAction;
        }

        size = 1024;
        default_action = NoAction();
    }
    apply {
        if (hdr.ipv4.isValid()) {
            vxlan_set_vtep_ip_lpm.apply();
            if (vxlan_set_vni_lpm.apply().hit) {
                if (vxlan_set_nexthop_lpm.apply().hit) {
                    vxlan_forward_lpm.apply();
                }
            }
        }
    }
}


control vxlan_egress_encap(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action l2_forward(bit<48> smac, bit<48> dmac) {
        hdr.ethernet.srcAddr = smac;
        hdr.ethernet.dstAddr = dmac;
    }

    table l2_forward_lpm {

        key = {
            hdr.ipv4.dstAddr : lpm;
        }

        actions = {
            l2_forward;
            NoAction;
        }

        size = 1024;
        default_action = NoAction();
    }

    action vxlan_encap() {

        hdr.in_ethernet = hdr.ethernet;
        hdr.in_ipv4 = hdr.ipv4;

        hdr.ethernet.setValid();

        hdr.ipv4.setValid();
        hdr.ipv4.version = IP_VERSION_4;
        hdr.ipv4.ihl = IPV4_MIN_IHL;
        hdr.ipv4.diffserv = 0;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen
                            + (ETH_HDR_SIZE + IPV4_HDR_SIZE + UDP_HDR_SIZE + VXLAN_HDR_SIZE);
        hdr.ipv4.identification = 0x1513;
        hdr.ipv4.flags = 0;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = UDP_PROTO;
        hdr.ipv4.dstAddr = meta.nexthop;
        hdr.ipv4.srcAddr = meta.vtepIP;
        hdr.ipv4.hdrChecksum = 0;

        hdr.udp.setValid();
        hash(hdr.udp.srcPort, HashAlgorithm.crc16, (bit<13>)0, { hdr.in_ethernet }, (bit<32>)65536);
        hdr.udp.dstPort = UDP_PORT_VXLAN;
        hdr.udp.udpLen = hdr.ipv4.totalLen + (UDP_HDR_SIZE + VXLAN_HDR_SIZE);
        hdr.udp.checksum = 0;

        hdr.vxlan.setValid();
        hdr.vxlan.reserved = 0;
        hdr.vxlan.gid = 0;
        hdr.vxlan.flags = 0;
        hdr.vxlan.vni = meta.vxlan_vni;

    }

    apply {
        if (meta.vxlan_vni != 0) {
            vxlan_encap();
            if (hdr.vxlan.isValid()) {
                l2_forward_lpm.apply();
            }
        }
    }
}



control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    vxlan_ingress_encap() encap;
    vxlan_ingress_decap() decap;

    apply {
        if (hdr.vxlan.isValid()) {
            decap.apply(hdr, meta, standard_metadata);
        }
        else {
            encap.apply(hdr, meta, standard_metadata);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    vxlan_egress_encap() encap;

    apply {

        if (!hdr.vxlan.isValid()) {
            encap.apply(hdr, meta, standard_metadata);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.in_ethernet);
        packet.emit(hdr.in_ipv4);

    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
