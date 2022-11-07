#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>


#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "sysemu/kvm.h"
#include "exec/gdbstub.h"

#include "hyperwall/utilities.h"


FILE *hyperwall_debug_file = NULL;
FILE *hyperwall_e1000_pcap_file = NULL;
bool hyperwall_was_lstar_init = false;
long unsigned int hyperwall_lstar = 0;

bool hyperwall_is_hooks_on = false;

long unsigned int hyperwall_kaslr_diff = 0;
long unsigned int system_map_sock_sendmsg = 0;
long unsigned int system_map_inet_dgram_ops = 0;
long unsigned int system_map_inet_stream_ops = 0;
long unsigned int system_map_inet_sockraw_ops = 0;
long unsigned int system_map_arp_xmit = 0;

static unsigned long int get_env_symbol(const char *name);


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

RB_HEAD(md5_hash_tree, hyperwall_md5_hash_tree_node) hyperwall_md5_hash_tree_head = RB_INITIALIZER(&hyperwall_md5_hash_tree_head);
RB_GENERATE(md5_hash_tree, hyperwall_md5_hash_tree_node, rb_entry, hyperwall_hash_comparator);

#pragma GCC diagnostic pop

int hyperwall_hash_comparator(struct hyperwall_md5_hash_tree_node *left, struct hyperwall_md5_hash_tree_node *right)
{
    return memcmp(left->hash, right->hash, MD5_HASH_LENGTH);
}

/// \param node Pointer to allocated hash
void hyperwall_insert_md5_hash(uint8_t *hash)
{
    struct hyperwall_md5_hash_tree_node *node = hyperwall_find_element(hash);
    if (node != NULL)
    {
        ++node->count;
        return;
    }

    struct hyperwall_md5_hash_tree_node *new_node = g_malloc(sizeof(struct hyperwall_md5_hash_tree_node));
    new_node->hash = hash;
    new_node->count = 1;
    (void) RB_INSERT(md5_hash_tree, &hyperwall_md5_hash_tree_head, new_node);
}

///
/// \param hash Pointer to hash that needs to be found in the tree and removed. The node is freed
void hyperwall_remove_md5_hash(uint8_t *hash)
{
    struct hyperwall_md5_hash_tree_node *node = hyperwall_find_element(hash);
//    assert(node != NULL);
    HYPER_RETURN_IF(node == NULL);

    if (--node->count == 0)
    {
        struct hyperwall_md5_hash_tree_node *result = RB_REMOVE(md5_hash_tree, &hyperwall_md5_hash_tree_head, node);
        assert(result != NULL);
        assert(result->hash != NULL);
        g_free(result->hash);
        g_free(result);
    }
}

struct hyperwall_md5_hash_tree_node *hyperwall_find_element(uint8_t *hash)
{
    struct hyperwall_md5_hash_tree_node node = {0};
    node.hash = hash;
    return RB_FIND(md5_hash_tree, &hyperwall_md5_hash_tree_head, &node);
}

bool hyperwall_contains_md5_hash(uint8_t *hash)
{
    return hyperwall_find_element(hash) != NULL;
}

uint8_t *hyperwall_hash(const uint8_t *buffer, size_t len)
{
    uint8_t *result_md5_hash = NULL;
    size_t hash_len = 0;
    Error *error = NULL;

    int result = qcrypto_hash_bytes(QCRYPTO_HASH_ALG_MD5, (const char *)buffer, len, &result_md5_hash, &hash_len, &error);
    HYPER_DEBUG("buffer = %u len = %u", buffer, len);
    if(result != 0)
    {
        HYPER_DEBUG("ERROR = %s", error_get_pretty(error));
    }
    HYPER_ASSERT(result == 0);
    HYPER_ASSERT(hash_len == MD5_HASH_LENGTH);

    return result_md5_hash;
}

bool hyperwall_consume_md5_hash(uint8_t *hash)
{
    bool is_md5_in_tree = hyperwall_contains_md5_hash(hash);
    HYPER_DEBUG("hyperwall_contains_md5_hash = %s", is_md5_in_tree ? "true" : "false");

    if(is_md5_in_tree)
    {
        hyperwall_remove_md5_hash(hash);
    }
    g_free(hash);
    return is_md5_in_tree;
}

void hyperwall_init(void)
{
    hyperwall_debug_file = fopen("/tmp/debug.txt", "a");
    hyperwall_e1000_pcap_file = fopen("/tmp/pcap.bin", "a");

    setbuf(hyperwall_e1000_pcap_file, NULL);

    fprintf(hyperwall_debug_file, "Hyperwall init success\n");
}

static unsigned long int get_env_symbol(const char *name)
{
    const char *env_string = getenv(name);
    if (env_string == NULL)
    {
        fprintf(hyperwall_debug_file, "%s env variable is not defined!\n", name);
        exit(1337);
    }

    errno = 0;
    unsigned long int result = strtoul(env_string, NULL, 0);
    if (errno != 0)
    {
        fprintf(hyperwall_debug_file, "strtoul(%s) failed with %d\n", name, errno);
        exit(1338);
    }

    return result;
}

void hyperwall_hook_init(void)
{
    long unsigned int system_map_entry_SYSCALL64 = get_env_symbol("SYSCALL64");

    hyperwall_kaslr_diff = hyperwall_lstar - system_map_entry_SYSCALL64;
    fprintf(hyperwall_debug_file, "hyperwall_kaslr_diff = %lu\n", hyperwall_kaslr_diff);

    system_map_sock_sendmsg = get_env_symbol("SOCK_SENDMSG") + hyperwall_kaslr_diff;
    fprintf(hyperwall_debug_file, "system_map_sock_sendmsg = %lu\n", system_map_sock_sendmsg);

    // 0xffffffff82346c40 D inet_dgram_ops
    // 0xffffffff82346d20 D inet_stream_ops
    // ffffffff82346b30 d inet_family_ops
    // ffffffff82346b60 d inet_sockraw_ops

    system_map_inet_dgram_ops = get_env_symbol("INET_DGRAM_OPS") + hyperwall_kaslr_diff;
    fprintf(hyperwall_debug_file, "system_map_inet_dgram_ops = %lu\n", system_map_inet_dgram_ops);

    system_map_inet_stream_ops = get_env_symbol("INET_STREAM_OPS") + hyperwall_kaslr_diff;
    fprintf(hyperwall_debug_file, "system_map_inet_stream_ops = %lu\n", system_map_inet_stream_ops);

    //// Not relevant since my solution tries all layers hashes instead of trying to smartly figure out which layer came
    // Yes relevant because I need to hash raw socket packets as well!!!
    system_map_inet_sockraw_ops = get_env_symbol("INET_SOCKRAW_OPS") + hyperwall_kaslr_diff;
    fprintf(hyperwall_debug_file, "system_map_inet_sockraw_ops = %lu\n", system_map_inet_sockraw_ops);

    system_map_arp_xmit = get_env_symbol("ARP_XMIT") + hyperwall_kaslr_diff;
    fprintf(hyperwall_debug_file, "system_map_arp_xmit = %lu\n", system_map_arp_xmit);

    CPUState *cs;
    CPU_FOREACH(cs) {
        fprintf(hyperwall_debug_file, "Inserting BP\n");
        // There are 5 nops at the start of the syscall, each of size 1
        kvm_insert_breakpoint(cs, system_map_sock_sendmsg, 5, GDB_BREAKPOINT_SW);
        kvm_insert_breakpoint(cs, system_map_arp_xmit, 5, GDB_BREAKPOINT_SW);
    }

    hyperwall_is_hooks_on = true;
}

void hyperwall_dump_hex(FILE *file, const void *data, size_t size)
{
    char ascii[17] = {0};
    unsigned char *bytes = (unsigned char *) data;
    for (size_t i = 0; i < size; ++i)
    {
        fprintf(file, "%02X ", bytes[i]);
        if (bytes[i] >= ' ' && bytes[i] <= '~')
        {
            ascii[i % 16] = bytes[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            fprintf(file, " ");
            if ((i + 1) % 16 == 0)
            {
                fprintf(file, "|  %s \n", ascii);
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    fprintf(file, " ");
                }
                for (size_t j = (i + 1) % 16; j < 16; ++j)
                {
                    fprintf(file, "   ");
                }
                fprintf(file, "|  %s \n", ascii);
            }
        }
    }

    fflush(file);
}