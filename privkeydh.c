/*
 * This file is part of tripledh.
 *
 * tripledh is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * tripledh is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with tripledh.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2016 Andrikopoulos Konstantinos  <mandragore@foss.ntua.gr>
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <gcrypt.h>

#include "privkeydh.h"
#include "dh.h"

gcry_error_t otrl_privkeydh_read_FILEp(DH_keypair *kp, FILE *privf)
{
    int privfd;
    struct stat st;
    unsigned char *buf;
    size_t s;
    gcry_error_t err;
    gcry_mpi_t privexp;

    if (!privf) {
        return gcry_error(GPG_ERR_NO_ERROR);
    }
    privfd = fileno(privf);
    if (fstat(privfd, &st)) {
        err = gcry_error_from_errno(errno);
        return err;
    }
    buf = malloc(st.st_size+1);
    if (!buf && st.st_size > 0) {
        return gcry_error(GPG_ERR_ENOMEM);
    }
    if(fread(buf, st.st_size, 1, privf) !=1) {
        err = gcry_error_from_errno(errno);
        free(buf);
        return err;
    }
    buf[st.st_size-1]='\0';
    privexp = gcry_mpi_snew(50);
    gcry_mpi_scan(&privexp, GCRYMPI_FMT_HEX, buf, 0, &s);

    otrl_dh_gen_keypair_with_exp(DH1536_GROUP_ID, kp, privexp);
    gcry_free(privexp);
    free(buf);
    return gcry_error(GPG_ERR_NO_ERROR);
}
