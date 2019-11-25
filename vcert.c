//
//  vcert.c
//  CertPath
//
//  Created by kong on 2019/10/31.
//  Copyright © 2019 kong. All rights reserved.
//

#include "vcert.h"
#include <string.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>


static BIO *bio_open_default(const char *filename, char *mode)
{
    BIO *bio = NULL;
    if (filename == NULL) {
        BIO_printf(bio, "Can`t open BIO.\n");
    } else{
        bio = BIO_new_file(filename, mode);
        if (bio != NULL) {
            return bio;
        }
    }
    return bio;
}

/* returns 1 for success and zero if an error occurred. */
static int load_pkcs12(BIO *in, const char *tpass,
                       EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *pass;
    int len, ret = 0;
    PKCS12 *p12;
    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        BIO_printf(in, "Error loading PKCS12 file.\n");
        goto die;
    }
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0)) {
        pass = "";
    } else {
        len = (int )strlen(tpass);
        if (len ) {
            BIO_printf(in, "Error PKCS12 Password for %s\n", tpass);
            goto die;
        }
        if (!PKCS12_verify_mac(p12, tpass, len)) {
            BIO_printf(in, "Error PKCS12 Password for %s\n", tpass);
            goto die;
        }
        pass = tpass;
    }
    ret = PKCS12_parse(p12, pass, pkey, cert, ca);
die:
    PKCS12_free(p12);
    return ret;
}

/* returns 1 for success and zero if an error occurred. */
X509 *load_cert(const char *file, int formart, const char *tpass)
{
    X509 *x509  = NULL;
    BIO  *bp    = NULL;
    if (file == NULL) {
        return x509;
    }
    if (file == NULL) {
        return x509;
    } else {
        bp = bio_open_default(file, "r");
    }
    if (bp == NULL) {
        goto end;
    }
    
    if (formart == FORMAT_ASN1) {
        x509 = d2i_X509_bio(bp, NULL);
    } else if (formart == FORMAT_PEM) {
        x509 = PEM_read_bio_X509_AUX(bp, NULL, NULL, NULL);
    } else if (formart == FORMAT_PKCS12) {
        if (!load_pkcs12(bp, tpass, NULL, &x509, NULL))
            goto end;
    } else {
        BIO_printf(bp, "Error bad input formart.\n");
        goto end;
    }
    if (x509 == NULL) {
        BIO_printf(bp, "Error unable to load Cert.\n");
    }
end:
    BIO_free(bp);
    return x509;
}

/* returns 1 for success and zero if an error occurred. */
X509_CRL *load_crl(const char *file, int formart)
{
    X509_CRL *x509_CRL = NULL;
    BIO *bp = NULL;
    
    if (file == NULL) {
        return x509_CRL;
    } else {
        bp = bio_open_default(file, "r");
    }
    if (bp == NULL) {
        goto end;
    }
    
    if (formart == FORMAT_ASN1) {
        x509_CRL = d2i_X509_CRL_bio(bp, NULL);
    } else if (formart == FORMAT_PEM) {
        x509_CRL =  PEM_read_bio_X509_CRL(bp, NULL, NULL, NULL);
    } else {
        BIO_printf(bp, "Error unable to load CRL.\n");
        goto end;
    }
    if (x509_CRL == NULL) {
        BIO_printf(bp, "Error unable to load PEM.\n");
        goto end;
    }
end:
    BIO_free(bp);
    return x509_CRL;
}

int load_certs(const char *files[], int num, int format, const char *pass, STACK_OF(X509) **pcerts)
{
    X509 *x509 = NULL;
    int rv = 0;
    int i;
    if (files == NULL) {
        return rv;
    }
    for (i = 0; i < num; i++) {
        const char *file = files[i];
        x509 = load_cert(file, format, pass);
        if (x509 != NULL && pcerts != NULL && *pcerts != NULL)
            sk_X509_push(*pcerts, x509);
    }
    if (pcerts != NULL && sk_X509_num(*pcerts) > 0) {
        rv = 1;
    }
    return rv;
}

int load_crls(const char *files[], int num, int format, const char *pass, STACK_OF(X509_CRL) **pcrls)
{
    X509_CRL *x509_CRL = NULL;
    int rv = 0;
    int i;
    if (files == NULL) {
        return rv;
    }
    for (i = 0; i < num; i++) {
        const char *file = files[i];
        x509_CRL = load_crl(file, format);
        if (x509_CRL != NULL && pcrls != NULL && *pcrls != NULL)
            sk_X509_CRL_push(*pcrls, x509_CRL);
    }
    if (pcrls != NULL && sk_X509_CRL_num(*pcrls) > 0) {
        rv = 1;
     }
    return rv;
}




