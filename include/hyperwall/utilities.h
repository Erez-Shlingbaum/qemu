#ifndef QEMU_HYPERWALL_H
#define QEMU_HYPERWALL_H

#include <stdio.h>
#include <stdbool.h>
#include "crypto/hash.h"

#include "hyperwall/bsd_tree.h"

#define HYPER_DEBUG(format, args...) do { \
        fprintf(hyperwall_debug_file, "%s:%u:%s(): " format "\n", __FILE__, __LINE__, __func__, ##args); \
        fflush(hyperwall_debug_file);         \
    } while (false)

#define HYPER_RETURN_IF(condition)                  \
    if(condition)                                   \
    {                                               \
        HYPER_DEBUG("RETURN_IF True: " #condition); \
        return;                                     \
    }

#define HYPER_RETURN_IF_NO_LOG(condition)                  \
    if(condition)                                   \
    {                                               \
        return;                                     \
    }


#define HYPER_RETURN_VAL_IF(condition, value)                  \
    if(condition)                                              \
    {                                                          \
        HYPER_DEBUG("RETURN_VAL_IF True: " #condition " | value = " #value); \
        return value;                                          \
    }

#define HYPER_ASSERT(condition) if(!(condition)) { HYPER_DEBUG("HYPER_ASSERT: " #condition); exit(-1); }

#define MD5_HASH_LENGTH 16ul

extern FILE *hyperwall_debug_file;
extern FILE *hyperwall_e1000_pcap_file;
extern bool hyperwall_was_lstar_init;

extern long unsigned int hyperwall_kaslr_diff;
extern long unsigned int hyperwall_lstar;

extern long unsigned int system_map_sock_sendmsg;
extern long unsigned int system_map_inet_dgram_ops;
extern long unsigned int system_map_inet_stream_ops;
extern long unsigned int system_map_inet_sockraw_ops;
extern long unsigned int system_map_packet_ops;
extern long unsigned int system_map_arp_xmit;

extern bool hyperwall_is_hooks_on;

void hyperwall_init(void);
void hyperwall_dump_hex(FILE *file, const void *data, size_t size);

/**
 * This function is called when VM OS writes to LSTAR MSR, and this function assumes "hyperwall_lstar" has a valid value
 */
void hyperwall_hook_init(void);

struct hyperwall_md5_hash_tree_node
{
    // RB stuff
    RB_ENTRY(hyperwall_md5_hash_tree_node)
    rb_entry;

    // Hyperwall stuff
    uint8_t *hash;
    size_t count;
};

int hyperwall_hash_comparator(struct hyperwall_md5_hash_tree_node *left, struct hyperwall_md5_hash_tree_node *right);

struct hyperwall_md5_hash_tree_node *hyperwall_find_element(uint8_t *hash);
bool hyperwall_contains_md5_hash(uint8_t *hash);

///
/// \return pointer to md5 hash of size 16. Needs to be freed with g_free(hash)
uint8_t *hyperwall_hash(const uint8_t *buffer, size_t len);

///
/// \brief Checks if hash is in hyperwall tree and removes it. Either way, hash gets g_free'd
/// \param hash md5 hash
/// \return true if hash was in tree, false if not
bool hyperwall_consume_md5_hash(uint8_t *hash);


void hyperwall_insert_md5_hash(uint8_t *hash);
void hyperwall_remove_md5_hash(uint8_t *hash);

extern struct md5_hash_tree hyperwall_md5_hash_tree_head;

/* Linux kernel structs */
struct list_head
{
    struct list_head *next, *prev;
};

struct llist_node
{
    struct llist_node *next;                 /*     0     8 */

    /* size: 8, cachelines: 1, members: 1 */
    /* last cacheline: 8 bytes */
};

struct hlist_head
{
    struct hlist_node *first;
};

struct hlist_node
{
    struct hlist_node *next, **pprev;
};

typedef enum
{
    SS_FREE = 0,            /* not allocated		*/
    SS_UNCONNECTED,            /* unconnected to any socket	*/
    SS_CONNECTING,            /* in process of connecting	*/
    SS_CONNECTED,            /* connected to socket		*/
    SS_DISCONNECTING        /* in process of disconnecting	*/
} socket_state;

/**
 *  struct socket - general BSD socket
 *  @state: socket state (%SS_CONNECTED, etc)
 *  @type: socket type (%SOCK_STREAM, etc)
 *  @flags: socket flags (%SOCK_NOSPACE, etc)
 *  @ops: protocol specific socket operations
 *  @file: File back pointer for gc
 *  @sk: internal networking protocol agnostic socket representation
 *  @wq: wait queue for several uses
 */
struct kernel_socket
{
    socket_state state;
    short type;
    unsigned long flags;

    // struct file*
    void *file;

    // struct sock*
    void *sk;
    // const struct proto_ops*
    const void *ops;
//    struct socket_wq wq; not relevant to this research
};

struct kernel_iovec
{
    void *iov_base;    /* __user. BSD uses caddr_t (1003.1g requires void *) */
    __kernel_size_t iov_len; /* Must be size_t (1003.1g) */
};


struct iov_iter
{
    uint8_t iter_type;
    bool nofault;
    bool data_source;
    size_t iov_offset;
    size_t count;

    const struct kernel_iovec *iov;

    union
    {
        unsigned long nr_segs;
        struct
        {
            unsigned int head;
            unsigned int start_head;
        };
        loff_t xarray_start;
    };
};


struct kernel_msghdr
{
    void *msg_name;    /* ptr to socket address structure */
    int msg_namelen;    /* size of socket address structure */
    struct iov_iter msg_iter;    /* data */

    /*
     * Ancillary data. msg_control_user is the user buffer used for the
     * recv* side when msg_control_is_user is set, msg_control is the kernel
     * buffer used for all other cases.
     */
    union
    {
        void *msg_control;
        void *msg_control_user; // __user
    };
    bool msg_control_is_user: 1;
    __kernel_size_t msg_controllen;    /* ancillary data buffer length */
    unsigned int msg_flags;    /* flags on received message */
    void *msg_iocb;    /* ptr to iocb for async requests */
};

// Different from hyperwall red black tree
struct rb_node
{
    unsigned long __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
/* The alignment might seem pointless, but allegedly CRIS needs it */


union ktime
{
    int64_t tv64;
//#if BITS_PER_LONG != 64 && !defined(CONFIG_KTIME_SCALAR)
    struct
    {
        int32_t nsec, sec;
    } tv;
//#endif
};

typedef union ktime ktime_t;        /* Kill this */


//#ifdef NET_SKBUFF_DATA_USES_OFFSET
typedef unsigned int sk_buff_data_t;
//#else
//typedef unsigned char *sk_buff_data_t;
//#endif

// TODO: from vmlinux syms
typedef uint32_t refcount_t;

//typedef uint8_t __u8;
//typedef uint16_t __u16;
//typedef uint32_t __u32;
//typedef uint64_t __u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;


/**
 *	struct sk_buff - socket buffer
 *	@next: Next buffer in list
 *	@prev: Previous buffer in list
 *	@tstamp: Time we arrived/left
 *	@skb_mstamp_ns: (aka @tstamp) earliest departure time; start point
 *		for retransmit timer
 *	@rbnode: RB tree node, alternative to next/prev for netem/tcp
 *	@list: queue head
 *	@sk: Socket we are owned by
 *	@ip_defrag_offset: (aka @sk) alternate use of @sk, used in
 *		fragmentation management
 *	@dev: Device we arrived on/are leaving by
 *	@dev_scratch: (aka @dev) alternate use of @dev when @dev would be %NULL
 *	@cb: Control buffer. Free for use by every layer. Put private vars here
 *	@_skb_refdst: destination entry (with norefcount bit)
 *	@sp: the security path, used for xfrm
 *	@len: Length of actual data
 *	@data_len: Data length
 *	@mac_len: Length of link layer header
 *	@hdr_len: writable header length of cloned skb
 *	@csum: Checksum (must include start/offset pair)
 *	@csum_start: Offset from skb->head where checksumming should start
 *	@csum_offset: Offset from csum_start where checksum should be stored
 *	@priority: Packet queueing priority
 *	@ignore_df: allow local fragmentation
 *	@cloned: Head may be cloned (check refcnt to be sure)
 *	@ip_summed: Driver fed us an IP checksum
 *	@nohdr: Payload reference only, must not modify header
 *	@pkt_type: Packet class
 *	@fclone: skbuff clone status
 *	@ipvs_property: skbuff is owned by ipvs
 *	@inner_protocol_type: whether the inner protocol is
 *		ENCAP_TYPE_ETHER or ENCAP_TYPE_IPPROTO
 *	@remcsum_offload: remote checksum offload is enabled
 *	@offload_fwd_mark: Packet was L2-forwarded in hardware
 *	@offload_l3_fwd_mark: Packet was L3-forwarded in hardware
 *	@tc_skip_classify: do not classify packet. set by IFB device
 *	@tc_at_ingress: used within tc_classify to distinguish in/egress
 *	@redirected: packet was redirected by packet classifier
 *	@from_ingress: packet was redirected from the ingress path
 *	@peeked: this packet has been seen already, so stats have been
 *		done for it, don't do them again
 *	@nf_trace: netfilter packet trace flag
 *	@protocol: Packet protocol from driver
 *	@destructor: Destruct function
 *	@tcp_tsorted_anchor: list structure for TCP (tp->tsorted_sent_queue)
 *	@_nfct: Associated connection, if any (with nfctinfo bits)
 *	@nf_bridge: Saved data about a bridged frame - see br_netfilter.c
 *	@skb_iif: ifindex of device we arrived on
 *	@tc_index: Traffic control index
 *	@hash: the packet hash
 *	@queue_mapping: Queue mapping for multiqueue devices
 *	@head_frag: skb was allocated from page fragments,
 *		not allocated by kmalloc() or vmalloc().
 *	@pfmemalloc: skbuff was allocated from PFMEMALLOC reserves
 *	@active_extensions: active extensions (skb_ext_id types)
 *	@ndisc_nodetype: router type (from link layer)
 *	@ooo_okay: allow the mapping of a socket to a queue to be changed
 *	@l4_hash: indicate hash is a canonical 4-tuple hash over transport
 *		ports.
 *	@sw_hash: indicates hash was computed in software stack
 *	@wifi_acked_valid: wifi_acked was set
 *	@wifi_acked: whether frame was acked on wifi or not
 *	@no_fcs:  Request NIC to treat last 4 bytes as Ethernet FCS
 *	@encapsulation: indicates the inner headers in the skbuff are valid
 *	@encap_hdr_csum: software checksum is needed
 *	@csum_valid: checksum is already valid
 *	@csum_not_inet: use CRC32c to resolve CHECKSUM_PARTIAL
 *	@csum_complete_sw: checksum was completed by software
 *	@csum_level: indicates the number of consecutive checksums found in
 *		the packet minus one that have been verified as
 *		CHECKSUM_UNNECESSARY (max 3)
 *	@dst_pending_confirm: need to confirm neighbour
 *	@decrypted: Decrypted SKB
 *	@napi_id: id of the NAPI struct this skb came from
 *	@sender_cpu: (aka @napi_id) source CPU in XPS
 *	@secmark: security marking
 *	@mark: Generic packet mark
 *	@reserved_tailroom: (aka @mark) number of bytes of free space available
 *		at the tail of an sk_buff
 *	@vlan_present: VLAN tag is present
 *	@vlan_proto: vlan encapsulation protocol
 *	@vlan_tci: vlan tag control information
 *	@inner_protocol: Protocol (encapsulation)
 *	@inner_ipproto: (aka @inner_protocol) stores ipproto when
 *		skb->inner_protocol_type == ENCAP_TYPE_IPPROTO;
 *	@inner_transport_header: Inner transport layer header (encapsulation)
 *	@inner_network_header: Network layer header (encapsulation)
 *	@inner_mac_header: Link layer header (encapsulation)
 *	@transport_header: Transport layer header
 *	@network_header: Network layer header
 *	@mac_header: Link layer header
 *	@kcov_handle: KCOV remote handle for remote coverage collection
 *	@tail: Tail pointer
 *	@end: End pointer
 *	@head: Head of buffer
 *	@data: Data head pointer
 *	@truesize: Buffer size
 *	@users: User count - see {datagram,tcp}.c
 *	@extensions: allocated extensions, valid if active_extensions is nonzero
 */
struct sk_buff
{
    // Fields that are commented out are not needed and helps avoid including more struct definitions
    union
    {
        struct
        {
            /* These two members must be first. */
            struct sk_buff *next;
            struct sk_buff *prev;

            union
            {
//                struct net_device *dev;
                void *dev;
                /* Some protocols might use this space to store information,
                 * while device pointer would be NULL.
                 * UDP receive path is one user.
                 */
                unsigned long dev_scratch;
            };
        };
        struct rb_node rbnode; /* used in netem, ip4 defrag, and tcp stack */
        struct list_head list;
    };

    union
    {
//        struct sock *sk; I think that this is kernel_socket
        struct kernel_socket *sk;
        int ip_defrag_offset;
    };

    union
    {
        ktime_t tstamp;
        uint64_t skb_mstamp_ns; /* earliest departure time */
    };
    /*
     * This is the control buffer. It is free to use for every
     * layer. Please put your private variables there. If you
     * want to keep them across layers you have to do a skb_clone()
     * first. This is owned by whoever has the skb queued ATM.
     */
//    char cb[48] __aligned(8);
    char cb[48] __attribute__ ((aligned (8)));

    union
    {
        struct
        {
            unsigned long _skb_refdst;
            void (*destructor)(struct sk_buff *skb);
        };

        struct list_head tcp_tsorted_anchor;
    };
    // CONFIG_NF_CONNTRACK=m
//#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
    unsigned long _nfct;
//#endif
    unsigned int len,
            data_len;
    uint16_t mac_len,
            hdr_len;

    /* Following fields are _not_ copied in __copy_skb_header()
     * Note that queue_mapping is here mostly to fill a hole.
     */
    uint16_t queue_mapping;

/* if you move cloned around you also must adapt those constants */
//#ifdef __BIG_ENDIAN_BITFIELD
//#define CLONED_MASK	(1 << 7)
//#else
//#define CLONED_MASK    1
//#endif
//#define CLONED_OFFSET()        offsetof(struct sk_buff, __cloned_offset)

    /* private: */
    uint8_t __cloned_offset[0];
    /* public: */
    uint8_t cloned: 1,
            nohdr: 1,
            fclone: 2,
            peeked: 1,
            head_frag: 1,
            pfmemalloc: 1;

    // CONFIG_SKB_EXTENSIONS=y
    //#ifdef CONFIG_SKB_EXTENSIONS
    uint8_t active_extensions;
//#endif

    /* fields enclosed in headers_start/headers_end are copied
     * using a single memcpy() in __copy_skb_header()
     */
    /* private: */
    uint32_t headers_start[0];
    /* public: */

/* if you move pkt_type around you also must adapt those constants */
//#ifdef __BIG_ENDIAN_BITFIELD
//#define PKT_TYPE_MAX	(7 << 5)
//#else
#define PKT_TYPE_MAX    7
//#endif
#define PKT_TYPE_OFFSET()    offsetof(struct sk_buff, __pkt_type_offset)

    /* private: */
    uint8_t __pkt_type_offset[0];
    /* public: */
    uint8_t pkt_type: 3;
    uint8_t ignore_df: 1;
    uint8_t nf_trace: 1;
    uint8_t ip_summed: 2;
    uint8_t ooo_okay: 1;

    uint8_t l4_hash: 1;
    uint8_t sw_hash: 1;
    uint8_t wifi_acked_valid: 1;
    uint8_t wifi_acked: 1;
    uint8_t no_fcs: 1;
    /* Indicates the inner headers are valid in the skbuff. */
    uint8_t encapsulation: 1;
    uint8_t encap_hdr_csum: 1;
    uint8_t csum_valid: 1;

//#ifdef __BIG_ENDIAN_BITFIELD
//#define PKT_VLAN_PRESENT_BIT	7
//#else
#define PKT_VLAN_PRESENT_BIT    0
//#endif
#define PKT_VLAN_PRESENT_OFFSET()    offsetof(struct sk_buff, __pkt_vlan_present_offset)
    /* private: */
    uint8_t __pkt_vlan_present_offset[0];
    /* public: */
    uint8_t vlan_present: 1;
    uint8_t csum_complete_sw: 1;
    uint8_t csum_level: 2;
    uint8_t csum_not_inet: 1;
    uint8_t dst_pending_confirm: 1;

    // CONFIG_IPV6_NDISC_NODETYPE=y
//#ifdef CONFIG_IPV6_NDISC_NODETYPE
    uint8_t ndisc_nodetype: 2;
//#endif

    uint8_t ipvs_property: 1;
    uint8_t inner_protocol_type: 1;
    uint8_t remcsum_offload: 1;
    // CONFIG_NET_SWITCHDEV=y
//#ifdef CONFIG_NET_SWITCHDEV
    uint8_t offload_fwd_mark: 1;
    uint8_t offload_l3_fwd_mark: 1;
//#endif

// CONFIG_NET_CLS_ACT=y
//#ifdef CONFIG_NET_CLS_ACT
    uint8_t tc_skip_classify: 1;
    uint8_t tc_at_ingress: 1;
//#endif

// CONFIG_NET_REDIRECT=y
//#ifdef CONFIG_NET_REDIRECT
    uint8_t redirected: 1;
    uint8_t from_ingress: 1;
//#endif

// CONFIG_TLS_DEVICE=y
//#ifdef CONFIG_TLS_DEVICE
    uint8_t decrypted: 1;
//#endif

// CONFIG_NET_SCHED=y
//#ifdef CONFIG_NET_SCHED
    uint16_t tc_index;    /* traffic control index */
//#endif

    union
    {
//        __wsum csum;
        uint32_t csum; // from reading the sources
        struct
        {
            uint16_t csum_start;
            uint16_t csum_offset;
        };
    };
    uint32_t priority;
    int skb_iif;
    uint32_t hash;

//    __be16 vlan_proto;
    uint16_t vlan_proto;

    uint16_t vlan_tci;

    // CONFIG_NET_RX_BUSY_POLL=y CONFIG_XPS=y
//#if defined(CONFIG_NET_RX_BUSY_POLL) || defined(CONFIG_XPS)
    union
    {
        unsigned int napi_id;
        unsigned int sender_cpu;
    };
//#endif
// CONFIG_NETWORK_SECMARK=y
//#ifdef CONFIG_NETWORK_SECMARK
    uint32_t secmark;
//#endif

    union
    {
        uint32_t mark;
        uint32_t reserved_tailroom;
    };

    union
    {
//        __be16 inner_protocol;
        uint16_t inner_protocol;
        uint8_t inner_ipproto;
    };

    uint16_t inner_transport_header;
    uint16_t inner_network_header;
    uint16_t inner_mac_header;

//    __be16 protocol;
    uint16_t protocol;
    uint16_t transport_header;
    uint16_t network_header;
    uint16_t mac_header;

    // CONFIG_KCOV is not set
//#ifdef CONFIG_KCOV
//    uint64_t			kcov_handle;
//#endif

    /* private: */
    uint32_t headers_end[0];
    /* public: */

    /* These elements must be at the end, see alloc_skb() for details.  */
    sk_buff_data_t tail;
    sk_buff_data_t end;
    unsigned char *head,
            *data;
    unsigned int truesize;
    refcount_t users;

    // CONFIG_SKB_EXTENSIONS=y
//#ifdef CONFIG_SKB_EXTENSIONS
//    /* only useable after checking ->active_extensions != 0 */
//    struct skb_ext		*extensions;
    void *extensions;
//#endif
};


#endif