//
//  vchain.h
//  CertPath
//
//  Created by kong on 2019/10/31.
//  Copyright © 2019 kong. All rights reserved.
//

#ifndef vchain_h
#define vchain_h

#include <stdio.h>

/// 校验证书链与crl
/// @param certs  证书数组
/// @param rnum   证书数组个数
/// @param crl    吊销证书列表数组
/// @param lnum   吊销证书列表个数
/// @param format FORMAT_ASN1, FORMAT_PEM
/// @param cert   待校验证书
int verify_cert(const char *certs[], const int rnum,
                const char *crls[],  const int lnum,
                const int   format,
                const char *cert);

#endif /* vchain_h */
