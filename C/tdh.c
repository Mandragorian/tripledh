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
 * Copyright (C) 2016 Andrikopoulos Konstantinos <mandragore@foss.ntua.gr>
 */


#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>
#include <string.h>

#include "dh.h"
#include "privkeydh.h"
#include "debug.h"

#define SESSID_LEN 8


/*
 * This struct is used internally to store the cryptographic algorithms for
 * sending and receiving the confirmation message of the triple dh exchange
 */
typedef struct {


    gcry_cipher_hd_t sendenc;           /* Sending cipher for confirmation message */

    gcry_cipher_hd_t rcvenc;            /* Receiving cipher for confirmation message */

    gcry_md_hd_t sendmac;               /* Sending mac for confirmation message */

    gcry_md_hd_t rcvmac;                /* Receiving mac for confirmation message */

    unsigned char sessionid[SESSID_LEN];        /* Session id for this exchange */

} TDH_state;


/*
 * This struct is seen by the end users. It stores all necessary information
 * needed to perform the exchange, from computing the shared secret to the
 * crypto algorithms needed to send and receive the confirmation messages
 */
typedef struct {
    DH_keypair longterm;                /* Our long term DH key */
    DH_keypair ephemeral;               /* Our ephemeral key just for this exchange */

    gcry_mpi_t their_pub_long;          /* Their long term public key */
    gcry_mpi_t their_pub_eph;           /* Their ephemeral public key */

    TDH_state state;                    /* Crypto algorithms to be used */

} TripleDH_handshake;



/*
 * Initialises a triple dh handshake
 */
void tripledh_handshake_init(TripleDH_handshake *handshake)
{
    otrl_dh_keypair_init(&handshake->longterm);
    otrl_dh_keypair_init(&handshake->ephemeral);

    handshake->their_pub_long = NULL;
    handshake->their_pub_eph  = NULL;

    handshake->state.sendenc = NULL;
    handshake->state.rcvenc  = NULL;
    handshake->state.sendmac = NULL;
    handshake->state.rcvmac  = NULL;

}

/*
 * Loads our long term keypair longterm in handshake to be used for computing
 * the shared secret
 */
void tripledh_handshake_load_longterm(TripleDH_handshake *handshake,
        DH_keypair *longterm)
{

    otrl_dh_keypair_copy(&(handshake->longterm), longterm);
    return;
}

/*
 * Generates an ephemeral dh key just for this handshake. This is the key
 * that will be authenticated to the other party deniably
 */
gcry_error_t tripledh_handshake_gen_ephemeral(TripleDH_handshake *handshake)
{
    gcry_error_t err;
    err = otrl_dh_gen_keypair(DH1536_GROUP_ID, &handshake->ephemeral);
    return err;
}

/*
 * Loads the other party's long term (their_long) and ephemeral (their_eph)
 * public keys needed for computing the shared secret
 */
gcry_error_t tripledh_handshake_load_their_pub(TripleDH_handshake *handshake,
        gcry_mpi_t their_long, gcry_mpi_t their_eph)
{
    /* Check if both longterm and ephemeral public keys are valid */
    if ( otrl_dh_is_inrange(their_long) ||
           otrl_dh_is_inrange(their_eph) ) {
        /*one of the public keys were out of range */
        debug_msg("pub keys out of range");
        return gcry_error(GPG_ERR_INV_VALUE);
    }
    debug_msg("loading pub keys \n");

    /* Just copy the provided public keys in the handshake data */
    handshake->their_pub_long = gcry_mpi_copy(their_long);
    handshake->their_pub_eph  = gcry_mpi_copy(their_eph);

    return gcry_error(GPG_ERR_NO_ERROR);
}

/*
 * Encrypt a message using the sending cipher in hs. If in is not null then
 * it must contain the message to be encrypted and inlen must have its size.
 * If in is NULL then inlen must be zero. In this case the message to be
 * encrypted must be in out and its length in outsize, and the encryption
 * will be performed in place. Overlapping buffers not allowed.
 * In any case if the function returns with no errors then out will have
 * the encrypted message and outsize will contain its length.
 *
 * This is just a wrapper around gcry_cipher_encrypt.
 */
gcry_error_t tripledh_handshake_encrypt(TripleDH_handshake *hs,
                                        unsigned char *out, size_t outsize,
                                        const unsigned *in, size_t inlen)
{
    gcry_error_t err;
    err = gcry_cipher_encrypt(hs->state.sendenc, out, outsize, in, inlen);
    return err;
}

/*
 * Decrypts a message using the receiving cipher in hs. Argument values
 * conform to the encryption pattern as above.
 *
 * This is just a wrapper around gcry_cipher_decrypt.
 */
gcry_error_t tripledh_handshake_decrypt(TripleDH_handshake *hs,
                                        unsigned char *out, size_t outsize,
                                        const unsigned char *in, size_t inlen)
{
    gcry_error_t err;
    err = gcry_cipher_decrypt(hs->state.rcvenc, out, outsize, in, inlen);
    return err;
}


/*
 * Generate the MAC of in using the sending HMAC in hs. The length of the
 * input is inlen. The MAC is returned in out which must be an allready
 * allocated buffer. Currently the size of the MAC is hardcoded to be 32
 * bytes.
 */
gcry_error_t tripledh_handshake_mac(TripleDH_handshake *hs,
                                    unsigned char *out, const unsigned char *in,
                                    size_t inlen)
{
    if (!in) {
        debug_msg("inline mac'ing not yet implemented");
        return gcry_error(GPG_ERR_NOT_IMPLEMENTED);
    }
    gcry_md_reset(hs->state.sendmac);
    gcry_md_write(hs->state.sendmac, in, inlen);
    memmove(out, gcry_md_read(hs->state.sendmac, GCRY_MD_SHA256), 32);
}


/*
 * Verify if mac is a valid MAC for msg, using receiving mac from hs
 */
gcry_error_t tripledh_handshake_mac_verify(TripleDH_handshake *hs,
                                           unsigned char mac[32],
                                           unsigned char *msg, size_t msglen)
{
    unsigned char my_mac[32];

    gcry_md_reset(hs->state.rcvmac);
    gcry_md_write(hs->state.rcvmac, msg, msglen);
    memmove(my_mac, gcry_md_read(hs->state.sendmac, GCRY_MD_SHA256), 32);

    return memcmp(my_mac, mac, 32);
}

/*
 * This function must be called after all the necessary values are loaded in
 * handshake and the ephemeral key is generated. It will then compute a session
 * id and sending and receiving ciphers/macs using the shared secret that can be
 * calculated by a triple dh exchange. The exchange is still NOT authenticated.
 */
gcry_error_t tripledh_handshake_compute_keys(TripleDH_handshake *handshake)
{
    gcry_mpi_t gab, gAb, gaB;
    size_t gab_len, gAb_len, gaB_len;
    size_t base = 0;
    unsigned char *sdata;
    unsigned char *hashdata;
    unsigned char ctr[16];
    unsigned char sendbyte, rcvbyte;
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    /* Init ctr to zero */
    memset(ctr, 0, 16);
    debug_msg("ctr set to zero\n");
    /* Alocate and calculate g^ab */
    gab = gcry_mpi_snew(700);
    if (!gab) {
        debug_msg("gab unallocated\n");
        return gcry_error(GPG_ERR_ENOMEM);
    }
    else {
        debug_msg("gab allocated\n");
    }

    if (!handshake->ephemeral.priv) {
        debug_msg("priv is not allocated\n");
        return gpg_error(GPG_ERR_GENERAL);
    }
    if (!handshake->their_pub_eph) {
        debug_msg("their_pub_eph is not allocated \n");
        return gpg_error(GPG_ERR_GENERAL);
    }

    otrl_dh_powm(gab, handshake->their_pub_eph, handshake->ephemeral.priv);
    debug_msg("gab calculated\n");
    /* Allocate  g^Ab */
    gAb = gcry_mpi_snew(700);

    /* Allocate g^aB */
    gaB = gcry_mpi_snew(700);


    /* We must decide if we are high or low in the exchange. To do so we
     * compare the longterm public keys. This is done because we calculate
     * values g^Ab and g^aB. Thus because we must concatenate them we must
     * decide in what order the concatenation happens. */
    if (gcry_mpi_cmp(handshake->longterm.pub, handshake->their_pub_long) > 0 ) {
        /* We are high */
        sendbyte = 0x01;
        rcvbyte  = 0x02;

        otrl_dh_powm(gAb, handshake->their_pub_eph, handshake->longterm.priv);
        otrl_dh_powm(gaB, handshake->their_pub_long, handshake->ephemeral.priv);

    }
    else {
        /* We are low */
        sendbyte = 0x02;
        rcvbyte  = 0x01;

        otrl_dh_powm(gaB, handshake->their_pub_eph, handshake->longterm.priv);
        otrl_dh_powm(gAb, handshake->their_pub_long, handshake->ephemeral.priv);
    }

    debug_msg("gab\n");
    debug_print_mpi(gab);
    debug_msg("gAb\n");
    debug_print_mpi(gAb);
    debug_msg("gaB\n");
    debug_print_mpi(gaB);
    debug_msg("exponentiations done\n");

    /* Get their respective lengths in the right format */
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &gab_len, gab);
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &gAb_len, gAb);
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &gaB_len, gaB);

    /* Allocate memory to store them as plain bytes. We need 4 extra bytes
     * for the length of each secret, plus one additional byte to use in key
     * derivation */
    sdata = gcry_malloc_secure(1 + 4 + gab_len + 4 + gAb_len + 4 + gaB_len);
    if (!sdata) {
        gcry_mpi_release(gab);
        gcry_mpi_release(gAb);
        gcry_mpi_release(gaB);
        return gcry_error(GPG_ERR_ENOMEM);
    }
    debug_msg("sdata allocated\n");

    /* Disregard first byte for now, write gab_len and then gab */
    sdata[1] = (gab_len >> 24) & 0xff;
    sdata[2] = (gab_len >> 16) & 0xff;
    sdata[3] = (gab_len >> 8) & 0xff;
    sdata[4] = gab_len & 0xff;
    gcry_mpi_print(GCRYMPI_FMT_USG, sdata+5, gab_len, NULL, gab);
    gcry_mpi_release(gab);
    /* Increase base by the bytes written */
    base += 4 + gab_len;

    /* Write gAb_len and then gAb */
    sdata[1+base] = (gAb_len >> 24) & 0xff;
    sdata[2+base] = (gAb_len >> 16) & 0xff;
    sdata[3+base] = (gAb_len >> 8) & 0xff;
    sdata[4+base] = gAb_len & 0xff;
    gcry_mpi_print(GCRYMPI_FMT_USG, sdata+base+5, gAb_len, NULL, gAb);
    gcry_mpi_release(gAb);
    /* Increase base by the bytes written */
    base += 4 + gAb_len;

    /* Write gaB_len and then gaB */
    sdata[1+base] = (gaB_len >> 24) & 0xff;
    sdata[2+base] = (gaB_len >> 16) & 0xff;
    sdata[3+base] = (gaB_len >> 8) & 0xff;
    sdata[4+base] = gaB_len & 0xff;
    gcry_mpi_print(GCRYMPI_FMT_USG, sdata+base+5, gaB_len,
            NULL, gaB);
    gcry_mpi_release(gaB);
    /* Increase base by the bytes written */
    base += 4 + gaB_len;

    debug_msg("sdata\n");
    debug_print_buffer(sdata,base+1);
    /* Calculate session id by hashing 0x00 || gab || gAb || gaB
     * and using the first 16 bytes of the hash */
    hashdata = gcry_malloc_secure(32);
    if (!hashdata) {
        gcry_free(sdata);
        return gcry_error(GPG_ERR_ENOMEM);
    }
    sdata[0] = 0x00;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);
    memmove(handshake->state.sessionid, hashdata, SESSID_LEN);

    /* Calculate sending encryption key by hashing  sendbyte || gab || gAb || gaB
     * and using the hash as the key */
    sdata[0] = sendbyte;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);
    debug_msg("send key\n");
    debug_print_buffer(hashdata,32);
    err = gcry_cipher_open(&(handshake->state.sendenc), GCRY_CIPHER_AES256,
            GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err) goto err;
    err = gcry_cipher_setkey(handshake->state.sendenc, hashdata, 32);
    if (err) goto err;
    err = gcry_cipher_setctr(handshake->state.sendenc, ctr, 16);
    if (err) goto err;

    /* Calculate the sending MAC key by hashing sendbyte+2 || gab || gAb || gaB
     * and using the whole hash as the key */
    sdata[0]= sendbyte + 2;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);

    err = gcry_md_open(&(handshake->state.sendmac), GCRY_MD_SHA256,
                       GCRY_MD_FLAG_HMAC);
    if (err) goto err;
    err = gcry_md_setkey(handshake->state.sendmac, hashdata, 32);
    if (err) goto err;

    /* Calculate receiving encryption key by hashing  rcvbyte || gab || gAb || gaB
     * and using the hash as the key */
    sdata[0] = rcvbyte;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);
    debug_msg("receiving key\n");
    debug_print_buffer(hashdata,32);
    err = gcry_cipher_open(&(handshake->state.rcvenc), GCRY_CIPHER_AES256,
            GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err) goto err;
    err = gcry_cipher_setkey(handshake->state.rcvenc, hashdata, 32);
    if (err) goto err;
    err = gcry_cipher_setctr(handshake->state.rcvenc, ctr, 16);
    if (err) goto err;

    /* Calculate the receiving MAC key by hashing rcvbyte+2 || gab || gAb || gaB
     * and using the hash as the key */
    sdata[0]= rcvbyte + 2;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, base+1);

    err = gcry_md_open(&(handshake->state.rcvmac), GCRY_MD_SHA256,
                       GCRY_MD_FLAG_HMAC);
    if (err) goto err;
    err = gcry_md_setkey(handshake->state.rcvmac, hashdata, 32);
    if (err) goto err;

    gcry_free(sdata);
    gcry_free(hashdata);
    return gcry_error(GPG_ERR_NO_ERROR);

err:
    gcry_cipher_close(handshake->state.sendenc);
    gcry_cipher_close(handshake->state.rcvenc);
    gcry_md_close(handshake->state.sendmac);
    gcry_md_close(handshake->state.rcvmac);

    handshake->state.sendenc = NULL;
    handshake->state.rcvenc  = NULL;
    handshake->state.sendmac = NULL;
    handshake->state.rcvmac  = NULL;

    gcry_free(sdata);
    gcry_free(hashdata);
    return err;
}



int main(int argc, char **argv)
{

    unsigned char * buf = NULL;
    gcry_mpi_t key = NULL;
    size_t written;
    gcry_error_t err;
    unsigned char message[16] = "must be readabl";
    unsigned char mac[32];
    FILE *fp;
    int i;
    TripleDH_handshake hs_a, hs_b;
    DH_keypair *a_keypair, *b_keypair;

    if(!gcry_check_version(NULL))
    {
	fputs("gcrypt version missmatch\n", stderr);
	exit(2);
    }

    //gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    otrl_dh_init();

    tripledh_handshake_init(&hs_a);
    tripledh_handshake_init(&hs_b);


    a_keypair = gcry_malloc_secure(sizeof(DH_keypair));
    b_keypair = gcry_malloc_secure(sizeof(DH_keypair));


    fp = fopen("apriv", "rb");

    otrl_privkeydh_read_FILEp(a_keypair, fp);

    fclose(fp);
    fopen("bpriv", "rb");

    otrl_privkeydh_read_FILEp(b_keypair, fp);

    fclose(fp);
    tripledh_handshake_load_longterm(&hs_a, a_keypair);
    tripledh_handshake_load_longterm(&hs_b, b_keypair);

    tripledh_handshake_gen_ephemeral(&hs_a);
    tripledh_handshake_gen_ephemeral(&hs_b);


    tripledh_handshake_load_their_pub(&hs_a, hs_b.longterm.pub,
                                       hs_b.ephemeral.pub);

    tripledh_handshake_load_their_pub(&hs_b, hs_a.longterm.pub,
                                      hs_a.ephemeral.pub);

    tripledh_handshake_compute_keys(&hs_a);
    tripledh_handshake_compute_keys(&hs_b);

    err = tripledh_handshake_encrypt(&hs_a, message, 16, NULL, 0);
    if(err)
        fprintf(stderr, "something went wrong when encrypting\n");
    fwrite(message, sizeof(unsigned char), 16, stderr);
    fprintf(stderr, "\n");
    tripledh_handshake_mac(&hs_a, mac, message, 16);

    for(i = 0; i<16; i++)
        fprintf(stderr, "%02X", mac[i]);
    fprintf(stderr,"\n");


    if(!tripledh_handshake_mac_verify(&hs_b, mac, message,16))
        fprintf(stderr,"message is not verified");
    err = tripledh_handshake_decrypt(&hs_b, message, 16, NULL, 0);
    if(err)
        fprintf(stderr, "something went wrong when decrypting\n");

    fprintf(stderr, "%s\n", message);

}
