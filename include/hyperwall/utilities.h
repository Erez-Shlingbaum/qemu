#ifndef QEMU_HYPERWALL_H
#define QEMU_HYPERWALL_H

#include <stdio.h>

extern FILE* hyperwall_debug_file;
extern FILE* hyperwall_e1000_pcap_file;

void dump_hex(FILE *file, const void *data, size_t size);

#endif