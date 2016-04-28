#include <gcrypt.h>
#include <stdio.h>


void print_buffer(const unsigned char *buf, size_t len)
{
    int i;
    for(i = 0; i<len;i++)
        fprintf(stderr,"%02X",buf[i]);
    fprintf(stderr,"\n");
}

void print_mpi(gcry_mpi_t to_print)
{
    unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,to_print);
    buf = malloc(s+2);
    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,to_print);
    buf[s-1]='\n';
    buf[s]='\0';
    fprintf(stderr, buf);
}

