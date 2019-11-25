#include <stdio.h>
#include "vchain.h"
#include "vcert.h"

int main() {

    const char *certs[] = {"./certs/root_ca.cer", "./certs/sub_ca.cer"};
    const char *curls[] = {"./certs/ca.crl"};

    printf("Verify unrevoked certificate: \n");
    char *cert = "./certs/leaf_ca.cer";
    int rv = verify_cert(certs, 2, curls, 1, FORMAT_ASN1, cert);
    if (rv == 1)
        printf("verify_cert success!\n");
    else
        printf("verify_cert fail!\n");

    printf("Verify revoked certificate: \n");
    cert = "./certs/leaf_ca_revoke.cer";
    rv = verify_cert(certs, 2, curls, 1, FORMAT_ASN1, cert);
    if (rv == 1)
        printf("verify_cert success!\n");
    else
        printf("verify_cert fail!\n");

    return 0;
 }
