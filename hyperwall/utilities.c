#include <stdio.h>
#include "hyperwall/utilities.h"

FILE* hyperwall_debug_file = NULL;
FILE* hyperwall_e1000_pcap_file = NULL;

void dump_hex(FILE *file, const void *data, size_t size)
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