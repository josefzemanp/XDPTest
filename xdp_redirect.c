#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} tx_port_map SEC(".maps");

SEC("xdp")
int xdp_redirect_icmp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)(ip + 1);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == ICMP_ECHO) {
        __u32 out_ifindex = 2;
        return bpf_redirect_map(&tx_port_map, out_ifindex, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
