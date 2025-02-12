#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

// Define a BPF map to store IP addresses of packets that should be dropped
struct {
    __uint(type, BPF_MAP_TYPE_HASH);  // Type of map - hash map
    __uint(max_entries, 100);          // Max number of entries in the map
    __type(key, __u32);                // Key type - 32-bit IP address
    __type(value, __u32);              // Value type - for simplicity, also a 32-bit integer
} drop_ip_map SEC(".maps"); // Pin the map for storage in BPF

// XDP program to drop ICMP Echo Requests from specific IP addresses
SEC("xdp") // this attaches the program to the XDP interface
int xdp_drop_icmp(struct xdp_md *ctx /* metadata about the packet */) {
    // Load pointers to the packet data and the end of the packet
    void *data_end = (void *)(long)ctx->data_end; // Pointer to the end of the packet data
    void *data = (void *)(long)ctx->data; // Pointer to the beginning of the packet data
    struct ethhdr *eth = data; // Pointer to the Ethernet header

    // Check if there is enough data for the Ethernet header
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // If there isn't enough data, pass the packet

    // Check if the Ethernet protocol is IPv4 (ETH_P_IP is used for IPv4)
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS; // If it's not IPv4, pass the packet

    // Parse the IP header
    struct iphdr *ip = (void *)(eth + 1);
    // Check if there is enough data for the IP header
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS; // If there isn't enough data, pass the packet

    // Check if the protocol is ICMP
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS; // If it's not ICMP, pass the packet

    // Parse the ICMP header
    struct icmphdr *icmp = (void *)(ip + 1);
    // Check if there is enough data for the ICMP header
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS; // If there isn't enough data, pass the packet

    // Check if the ICMP type is Echo Request (ping)
    if (icmp->type == ICMP_ECHO) {
        __u32 ip_addr = ip->saddr; // Get the source IP address from the IP header
        
        // Check if this IP address is in the drop list (stored in the BPF map)
        __u32 *drop_entry = bpf_map_lookup_elem(&drop_ip_map, &ip_addr);
        if (drop_entry) {
            // If the IP address is found in the map, drop the packet
            return XDP_DROP;
        }
    }

    // If the packet is not an ICMP Echo Request or not in the drop list, pass the packet
    return XDP_PASS;
}

// License declaration for the BPF program
char _license[] SEC("license") = "GPL";
