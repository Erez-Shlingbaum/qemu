#ifndef QEMU_HYPERWALL_H
#define QEMU_HYPERWALL_H

#include <stdio.h>
#include <stdbool.h>

#include "hyperwall/bsd_tree.h"

extern FILE *hyperwall_debug_file;
extern FILE *hyperwall_e1000_pcap_file;
extern bool hyperwall_was_lstar_init;
extern long unsigned int hyperwall_lstar;
extern long unsigned int system_map_inet_dgram_ops;
extern long unsigned int system_map_inet_stream_ops;

extern bool is_sock_sendmsg_hooked;

void hyperwall_init(void);
void hyperwall_dump_hex(FILE *file, const void *data, size_t size);

/**
 * This function is called when VM OS writes to LSTAR MSR, and this function assumes "hyperwall_lstar" has a valid value
 */
void hyperwall_hook_init(void);

struct md5_hash_tree_node
{
    RB_ENTRY(md5_hash_tree_node) entry;
    uint8_t *hash;
};

int hyperwall_hash_comparator(struct md5_hash_tree_node *left, struct md5_hash_tree_node *right);
void hyperwall_insert_md5_hash(struct md5_hash_tree_node *node);

extern struct md5_hash_tree hyperwall_md5_hash_tree_head;

/* Linux kernel structs */
typedef enum
{
    SS_FREE = 0,            /* not allocated		*/
    SS_UNCONNECTED,            /* unconnected to any socket	*/
    SS_CONNECTING,            /* in process of connecting	*/
    SS_CONNECTED,            /* connected to socket		*/
    SS_DISCONNECTING        /* in process of disconnecting	*/
} socket_state;

struct kernel_socket
{
    socket_state state;
    short type;
    unsigned long flags;
    void *file;
    void *sk;
    const void *ops;
//    struct socket_wq wq; not relevant
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

#endif