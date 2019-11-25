//
//  vcert.h
//  CertPath
//
//  Created by kong on 2019/10/31.
//  Copyright © 2019 kong. All rights reserved.
//
//  reference from openssl | apps/verify.c
//                         | apps/apps.c

#ifndef vcert_h
#define vcert_h

#include <stdio.h>
#include <openssl/x509.h>

/* FORMAT DEFINE */
#define FORMAT_UNDEF   0  /* UNDEF  ENCODE */
#define FORMAT_ASN1    1  /* ASN1   ENCODE */
#define FORMAT_PEM     2  /* PEM    ENCODE */
#define FORMAT_PKCS12  3  /* PKCS12 ENCDOE */


/// Load Certificate
/// @param file     File Path
/// @param formart  FORMAT_ASN1, FORMAT_PEM, FORMAT_PKCS12
/// @param tpass    Password
X509 *load_cert(const char *file, int formart, const char *tpass);


/// Load Crl
/// @param file     File Path
/// @param formart  FORMAT_ASN1, FORMAT_PEM
X509_CRL *load_crl(const char *file, int formart);



/// Load Certificates
/// @param files    Files
/// @param num      File number
/// @param format   FORMAT_ASN1, FORMAT_PEM, FORMAT_PKCS12
/// @param pass     Password
/// @param pcerts   pcerts
int load_certs(const char *files[], int num, int format, const char *pass, STACK_OF(X509) **pcerts);


/// Load Crls
/// @param files    Files
/// @param num      File number
/// @param format   FORMAT_ASN1, FORMAT_PEM
/// @param pass     Password
/// @param pcrls    pcrls
int load_crls(const char *files[], int num, int format, const char *pass, STACK_OF(X509_CRL) **pcrls);


#endif /* vcert_h */
