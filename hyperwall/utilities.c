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

bool is_sock_sendmsg_hooked = false;

long unsigned int aslr_diff = 0;
long unsigned int system_map_sock_sendmsg = 0;
long unsigned int system_map_inet_dgram_ops = 0;
long unsigned int system_map_inet_stream_ops = 0;

static unsigned long int get_env_symbol(const char *name);


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

RB_HEAD(md5_hash_tree, md5_hash_tree_node) hyperwall_md5_hash_tree_head = RB_INITIALIZER(&hyperwall_md5_hash_tree_head);
RB_GENERATE(md5_hash_tree, md5_hash_tree_node, entry, hyperwall_hash_comparator);

#pragma GCC diagnostic pop

int hyperwall_hash_comparator(struct md5_hash_tree_node *left, struct md5_hash_tree_node *right)
{
    return memcmp(left->hash, right->hash, 16ul);
}

void hyperwall_insert_md5_hash(struct md5_hash_tree_node *node)
{
    RB_INSERT(md5_hash_tree, &hyperwall_md5_hash_tree_head, node);
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

    aslr_diff = hyperwall_lstar - system_map_entry_SYSCALL64;
    fprintf(hyperwall_debug_file, "aslr_diff = %lu\n", aslr_diff);

    system_map_sock_sendmsg = get_env_symbol("SOCK_SENDMSG") + aslr_diff;
    fprintf(hyperwall_debug_file, "system_map_sock_sendmsg = %lu\n", system_map_sock_sendmsg);

    // 0xffffffff82346c40 D inet_dgram_ops
    // 0xffffffff82346d20 D inet_stream_ops

    system_map_inet_dgram_ops = get_env_symbol("INET_DGRAM_OPS") + aslr_diff;
    fprintf(hyperwall_debug_file, "system_map_inet_dgram_ops = %lu\n", system_map_inet_dgram_ops);

    system_map_inet_stream_ops = get_env_symbol("INET_STREAM_OPS") + aslr_diff;
    fprintf(hyperwall_debug_file, "system_map_inet_stream_ops = %lu\n", system_map_inet_stream_ops);

    CPUState *cs;
    CPU_FOREACH(cs) {
        fprintf(hyperwall_debug_file, "Inserting BP\n");
        // There are 5 nops at the start of the syscall, each of size 1
        kvm_insert_breakpoint(cs, system_map_sock_sendmsg, 5, GDB_BREAKPOINT_SW);
    }

    is_sock_sendmsg_hooked = true;
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