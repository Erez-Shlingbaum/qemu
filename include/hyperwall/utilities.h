#ifndef QEMU_HYPERWALL_H
#define QEMU_HYPERWALL_H

#include <stdio.h>
#include <stdbool.h>

extern FILE* hyperwall_debug_file;
extern FILE* hyperwall_e1000_pcap_file;
extern bool hyperwall_was_lstar_init;
extern long unsigned int hyperwall_lstar;

void hyperwall_init();
void hyperwall_dump_hex(FILE *file, const void *data, size_t size);

#endif