#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "hyperwall/utilities.h"

FILE* hyperwall_debug_file = NULL;
FILE* hyperwall_e1000_pcap_file = NULL;
bool hyperwall_was_lstar_init = false;
long unsigned int hyperwall_lstar = 0;

long unsigned int aslr_diff = 0;
long unsigned int system_map_sock_sendmsg = 0;

void hyperwall_init(void)
{
    hyperwall_debug_file = fopen("/tmp/debug.txt", "a");
    hyperwall_e1000_pcap_file = fopen("/tmp/pcap.bin", "a");
}

unsigned long int get_env_symbol(const char* name)
{
    const char* env_string = getenv(name);
    if(env_string == NULL)
    {
        fprintf(hyperwall_debug_file, "%s env variable is not defined!\n", name);
        exit(1337);
    }

    errno = 0;
    unsigned long int result = strtoul(env_string, NULL, 0);
    if(errno != 0)
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
}