#ifndef QEMU_HYPERWALL_H
#define QEMU_HYPERWALL_H

#include <stdio.h>
#include <stdbool.h>

extern FILE* hyperwall_debug_file;
extern FILE* hyperwall_e1000_pcap_file;
extern bool hyperwall_was_lstar_init;
extern long unsigned int hyperwall_lstar;

extern bool is_sock_sendmsg_hooked;

void hyperwall_init(void);
void hyperwall_dump_hex(FILE *file, const void *data, size_t size);

/**
 * This function is called when VM OS writes to LSTAR MSR, and this function assumes "hyperwall_lstar" has a valid value
 */
void hyperwall_hook_init(void);

#endif