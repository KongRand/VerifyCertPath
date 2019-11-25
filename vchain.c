//
//  vchain.c
//  CertPath
//
//  Created by kong on 2019/10/31.
//  Copyright © 2019 kong. All rights reserved.
//

#include "vchain.h"
#include "vcert.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/// 校验证书链与crl
/// @param certs 证书数组
/// @param rnum  证书数组个数
/// @param crl   吊销证书列表数组
/// @param lnum  吊销证书列表个数
/// @param cert  待校验证书
int verify_cert(const char *certs[], const int rnum,
                const char *crl[],   const int lnum,
                const int   format,
                const char *cert)
{
    int ret = 0;
    X509_STORE *store;
    X509_STORE_CTX *ctx;
    X509 *leaf;

    store = X509_STORE_new();
    ctx   = X509_STORE_CTX_new();
    leaf  = X509_new();
        
    STACK_OF(X509) *certs_stack = sk_X509_new_null();
    ret = load_certs(certs, rnum, format, "", &certs_stack);
     if (certs_stack == NULL) {
        ret = 0;
        goto end;
    }

    STACK_OF(X509_CRL) *crls_stack = sk_X509_CRL_new_null();
    load_crls(crl, lnum, format, "", &crls_stack);
    if (crls_stack == NULL) {
        ret = 0;
        goto end;
    }
    
    leaf = load_cert(cert, format, "");
    if (leaf == NULL) {
        ret = 0;
        goto end;
    }
    
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if (!ret) {
        ret = 0;
        goto end;
    }
     
    ret = X509_STORE_CTX_init(ctx, store, leaf, NULL);
    if (!ret) {
        ret = 0;
        goto end;
    }
    
    X509_STORE_CTX_set0_trusted_stack(ctx, certs_stack);
    X509_STORE_CTX_set0_crls(ctx, crls_stack);
    
    ret = X509_verify_cert(ctx);

end:
    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);
    X509_free(leaf);
    
    sk_X509_free(certs_stack);
    sk_X509_CRL_free(crls_stack);
    return ret;
}
