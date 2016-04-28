#ifndef __PRIVKEYDH_H__
#define __PRIVKEYDH_H__

#include <stdio.h>
#include <gcrypt.h>
#include <sys/stat.h>

#include "dh.h"

/*
 * Read a triple DH long term key from file privf
 */
gcry_error_t otrl_privkeydh_read_FILEp(DH_keypair *kp, FILE *privf);


#endif
