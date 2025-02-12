#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

// define a BPF map for redirecting packets to another network interface
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP); // map type: device map (associates interfaces with a destination)
    __uint(max_entries, 10); // maximum number of entries in the map
    __type(key, __u32); // key type in the map (network interface index)
    __type(value, __u32); // value type in the map (network interface index)
} tx_port_map SEC(".maps"); // pin the map for storage in BPF

// XDP program to filter ICMP echo requests and redirect them to another port
SEC("xdp") // program is attached to the XDP interface
int xdp_redirect_icmp(struct xdp_md *ctx /* metadata about the packet */) {
    // load pointers to the packet's data and end of data
    void *data_end = (void *)(long)ctx->data_end; // pointer to the end of the packet data
    void *data = (void *)(long)ctx->data; // pointer to the beginning of the packet data
    struct ethhdr *eth = data; // pointer to the Ethernet header

    // Check if there is enough data for the Ethernet header
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // if not enough data, pass the packet without modification

    // check if the protocol is IPv4 (Ethernet type for IP is ETH_P_IP)
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS; // if not IP, pass the packet without modification

    // parse the IP header
    struct iphdr *ip = (void *)(eth + 1);
    // check if there is enough data for the IP header
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS; // if not enough data, pass the packet

    // check if the IP protocol is ICMP
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS; // if not ICMP, pass the packet without modification

    // parse the ICMP header
    struct icmphdr *icmp = (void *)(ip + 1);
    // check if there is enough data for the ICMP header
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS; // if not enough data, pass the packet

    // check if the ICMP type is Echo Request (ping)
    if (icmp->type == ICMP_ECHO) {
        __u32 out_ifindex = 2; // Specify the output network interface index (interface 2)
        // redirect the packet to the specified interface using the map
        return bpf_redirect_map(&tx_port_map, out_ifindex, 0); 
    }

    // if its not an ICMP Echo Request, pass the packet
    return XDP_PASS;
}

// license declaration for the BPF program
char _license[] SEC("license") = "GPL";
