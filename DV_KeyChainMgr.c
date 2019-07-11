//
//  DV_KeyChainMgr.c
//
//  Created by Devil on 2019/3/18.
//  Copyright © 2019 Devil. All rights reserved.
//

#include "DV_KeyChainMgr.h"

//创建空的CFMutableDictionaryRef
#define newCFDict CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks)

//默认使用 通用密码 类型
#define defaultSecClass kSecClassGenericPassword

//默认的account值
CFStringRef dv_accountStringRef = CFSTR("DEFAULT_ACCOUNT");
//默认访问控制的值
CFOptionFlags dv_secAccessControl = kSecAccessControlUserPresence;
//默认的私钥名称
CFStringRef dv_priKeyName = CFSTR("com.devil.key.private");
//默认的公钥名称
CFStringRef dv_pubKeyName = CFSTR("com.devil.key.public");
//默认的公私钥名称(设置此值会同时修改上述两个值)
CFStringRef dv_keyPairName = CFSTR("com.devil.key");

/**
 设置新的account值（设置后本次app运行期间一直使用此值）

 @param ref 新的account值
 */
void dv_setAccountStringRef(CFStringRef ref)
{
    dv_accountStringRef = ref;
}

/**
 设置新的SecAccessControl值（设置后本次app运行期间一直使用此值）(默认为kSecAccessControlUserPresence，如不要访问控制设置成-1)
 @param flag 新的SecAccessControl值
 */
void dv_setSecAccessControl(CFOptionFlags flag)
{
    dv_secAccessControl = flag;
}

/**
 设置新的dv_keyPairName值（设置后本次app运行期间一直使用此值）
 @param name 新的dv_keyPairName值
 */
void dv_setKeyPairName(char *name)
{
    size_t newNameLen = strlen(name);
    
    size_t pubEndLen = strlen(".public");
    char *cStrPub = malloc(newNameLen+pubEndLen);
    memset(cStrPub, 0, newNameLen+pubEndLen);
    strcat(cStrPub,name);
    strcat(cStrPub+newNameLen,".public");
    dv_pubKeyName = CFStringCreateWithCString(kCFAllocatorDefault, cStrPub, kCFStringEncodingUTF8);
    free(cStrPub);
    
    size_t priEndLen = strlen(".private");
    char *cStrPri = malloc(newNameLen+priEndLen);
    memset(cStrPri, 0, newNameLen+priEndLen);
    strcat(cStrPri,name);
    strcat(cStrPri+newNameLen,".private");
    dv_priKeyName = CFStringCreateWithCString(kCFAllocatorDefault, cStrPri, kCFStringEncodingUTF8);
    free(cStrPri);
    
    dv_keyPairName = CFStringCreateWithCString(kCFAllocatorDefault, name, kCFStringEncodingUTF8);
}

/**
 初始化所有变量
 */
void dv_initAllVariable(void){
    //默认的account值
    dv_accountStringRef = CFSTR("DEFAULT_ACCOUNT");
    //默认的私钥名称
    dv_priKeyName = CFSTR("com.devil.key.private");
    //默认的公钥名称
    dv_pubKeyName = CFSTR("com.devil.key.public");
    //默认的公私钥名称(设置此值会同时修改上述两个值)
    dv_keyPairName = CFSTR("com.devil.key");
}


/**
 释放所有变量
 */
void dv_freeAllVariable(){
    if (dv_accountStringRef) {
        CFRelease(dv_accountStringRef);
    }
    if (dv_priKeyName) {
        CFRelease(dv_priKeyName);
    }
    if (dv_pubKeyName) {
        CFRelease(dv_pubKeyName);
    }
    if (dv_keyPairName) {
        CFRelease(dv_keyPairName);
    }
}

/**
 创建普通的通用的字典

 @param key 标识（键）
 @param secClass
    kSecClassGenericPassword(通用密码)
    kSecClassInternetPassword(互联网密码)
    kSecClassCertificate(证书)
    kSecClassKey(密钥)
    kSecClassIdentity(身份)
 @return 默认字典
 */
CFMutableDictionaryRef dv_createDefaultCFMutableDictionaryRefBykSecClass(CFStringRef secClass,CFStringRef key)
{
    CFMutableDictionaryRef dicRef = CFDictionaryCreateMutable(kCFAllocatorDefault, 1, NULL, NULL);
    if (secClass == kSecClassGenericPassword) {//通用密码
//        CFStringRef keys[4];
//        keys[0] = kSecClass;
//        keys[1] = kSecAttrAccount;
//        keys[2] = kSecAttrService;
//        keys[3] = kSecAttrGeneric;
//        CFTypeRef values[4];
//        values[0] = secClass;
//        values[1] = dv_accountStringRef;
//        values[2] = key;
//        values[3] = key;
//
//        for (int i = 0; i < 4; i ++) {
//            CFDictionarySetValue(dicRef, keys[i], values[i]);
//        }
        CFDictionarySetValue(dicRef, kSecClass, secClass);
        CFDictionarySetValue(dicRef, kSecAttrAccount, dv_accountStringRef);
        CFDictionarySetValue(dicRef, kSecAttrService, key);
        CFDictionarySetValue(dicRef, kSecAttrGeneric, key);
    }
    
    return dicRef;
}


/**
 查询KeyChain键值对

 @param key 键
 @param isNeedReturnData 是否需要返回查询的数据
 @return 需要返回数据时，返回的是查询到的数据，并且需要调用者自己释放(CFRelease(ref))。不需要返回数据时，返回kCFBooleanTrue(查询成功)或者kCFBooleanFalse(查询失败)
 */
CFTypeRef dv_keyChainQuery(CFStringRef key,CFBooleanRef isNeedReturnData)
{
    
    CFTypeRef result = NULL;
    CFMutableDictionaryRef dicRef = dv_createDefaultCFMutableDictionaryRefBykSecClass(defaultSecClass,key);
    CFDictionarySetValue(dicRef, kSecMatchLimit, kSecMatchLimitOne);
    //kCFBooleanTrue kCFBooleanFalse
    CFDictionarySetValue(dicRef, kSecReturnData, isNeedReturnData);

    
    OSStatus status = SecItemCopyMatching(dicRef, &result);
    
    CFRelease(dicRef);

    if (isNeedReturnData == kCFBooleanTrue) {
        return result;
    }else{
        if (status == 0) {
            return kCFBooleanTrue;
        }else{
            return kCFBooleanFalse;
        }
    }
    
}


/**
 增加KeyChain键值对

 @param key 键
 @param value 值
 @param isNeedAccessControl 是否需要访问控制
 @return OSStatus == errSecSuccess成功，其它失败
 */
OSStatus dv_keyChainAdd(CFStringRef key,CFDataRef value,CFBooleanRef isNeedAccessControl)
{
//    CFTypeRef result = NULL;
    CFMutableDictionaryRef dicRef = dv_createDefaultCFMutableDictionaryRefBykSecClass(defaultSecClass,key);
    CFDictionarySetValue(dicRef, kSecValueData, value);
    //是否需要添加访问控制
    if (isNeedAccessControl == kCFBooleanTrue) {
        CFErrorRef error = NULL;
        SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(
                                                                        kCFAllocatorDefault,
                                                                        kSecAttrAccessibleWhenUnlocked,
                                                                        dv_secAccessControl,
                                                                        &error
                                                                        );
        
        if (error) {
            printf("Generate key error");
//            CFRelease(error);
            return -1;
        }
        CFDictionarySetValue(dicRef, kSecAttrAccessControl, sacObject);
    }

    OSStatus status = SecItemAdd(dicRef, NULL);
    while (status == errSecDuplicateItem)
    {
        status = SecItemDelete(dicRef);
        status = SecItemAdd(dicRef, NULL);
    }
    CFRelease(dicRef);
//    if (result != NULL) {
//        CFRelease(result);
//    }
    
    return status;
}


/**
 修改KeyChain键值对

 @param key 需要修改的键
 @param value 新的值
 @return OSStatus == errSecSuccess成功，其它失败
 */
OSStatus dv_keyChainUpdate(CFStringRef key,CFDataRef value)
{
    
    CFMutableDictionaryRef queryDic = dv_createDefaultCFMutableDictionaryRefBykSecClass(defaultSecClass,key);
    CFMutableDictionaryRef updateDic = CFDictionaryCreateMutable(kCFAllocatorDefault, 1, NULL, NULL);
    CFDictionarySetValue(updateDic, kSecValueData, value);
    
    OSStatus status = SecItemUpdate(queryDic, updateDic);
    
    CFRelease(queryDic);
    CFRelease(updateDic);
    return status;
}

/**
 删除KeyChain键值对
 
 @param key 需要删除的键
 @return OSStatus == errSecSuccess成功，其它失败
 */
OSStatus dv_keyChainDelete(CFStringRef key)
{
   
    CFMutableDictionaryRef queryDic = dv_createDefaultCFMutableDictionaryRefBykSecClass(defaultSecClass,key);

    OSStatus status = SecItemDelete(queryDic);
    
    CFRelease(queryDic);
    
    return status;
}

/**
 保存生成的公钥信息
 
 @param publicKeyRef 公钥信息
 @return errSecSuccess成功 其它失败
 */
OSStatus savePubKeyFromRef(CFStringRef keyType,SecKeyRef publicKeyRef)
{
//    CFTypeRef keyBits;
    CFMutableDictionaryRef savePublicKeyDict = newCFDict;
    CFDictionaryAddValue(savePublicKeyDict, kSecClass, kSecClassKey);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrKeyType,  keyType);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrApplicationTag, dv_pubKeyName);
    CFDictionaryAddValue(savePublicKeyDict, kSecValueRef, publicKeyRef);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(savePublicKeyDict, kSecReturnData, kCFBooleanFalse);
    
    OSStatus err = SecItemAdd(savePublicKeyDict, NULL);
    while (err == errSecDuplicateItem)
    {
        err = SecItemDelete(savePublicKeyDict);
        err = SecItemAdd(savePublicKeyDict, NULL);
    }
    
    CFRelease(savePublicKeyDict);
    return err;
}


/**
 生成公私钥 Secure Enclave
 @params keyType
             kSecAttrKeyTypeRSA -- 2048
             kSecAttrKeyTypeEC -- 256
             kSecAttrKeyTypeECSECPrimeRandom -- 2048
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_secKeyGeneratePair(CFStringRef keyType)
{
    CFErrorRef error = NULL;
    // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
    CFOptionFlags sacFlags;
    if (keyType == kSecAttrKeyTypeEC) {
        sacFlags = kSecAccessControlUserPresence | kSecAccessControlPrivateKeyUsage;
    }else{
        sacFlags = kSecAccessControlUserPresence;
    }
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(
                                                                    kCFAllocatorDefault,
                                                                    kSecAttrAccessibleWhenUnlocked,
                                                                    sacFlags,
                                                                    &error
                                                                    );
    
    if (error != errSecSuccess) {
        printf("Generate key error");
        if (error != NULL) {
            CFRelease(error);
        }
        return -1;
    }
    // create dict of private key info
    CFMutableDictionaryRef accessControlDict = newCFDict;;
    CFDictionaryAddValue(accessControlDict, kSecAttrAccessControl, sacObject);
    CFDictionaryAddValue(accessControlDict, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(accessControlDict, kSecAttrLabel, dv_priKeyName);
    
    
    // create dict which actually saves key into keychain
    CFMutableDictionaryRef generatePairRef = newCFDict;
    if (keyType == kSecAttrKeyTypeEC) {
        CFDictionaryAddValue(generatePairRef, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);//表示使用SecureEnclave来保存密钥
        CFDictionaryAddValue(generatePairRef, kSecAttrKeyType, kSecAttrKeyTypeEC);//表示产生ECC密钥对，注意目前只支持256位的ECC算法
        int numBits = 256;
        CFDictionaryAddValue(generatePairRef, kSecAttrKeySizeInBits, CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &numBits));
    }else{
        CFDictionaryAddValue(generatePairRef, kSecAttrKeyType, keyType);
        int numBits = 2048;
        CFDictionaryAddValue(generatePairRef, kSecAttrKeySizeInBits, CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &numBits));
    }
    
    //设置私钥的属性配置
    CFDictionaryAddValue(generatePairRef, kSecPrivateKeyAttrs, accessControlDict);
    
    
    SecKeyRef publicKeyRef;
    SecKeyRef privateKeyRef;
    //删除旧的密钥对
    dv_deletePubKey(keyType);
    dv_deletePriKey();

    OSStatus status = SecKeyGeneratePair(generatePairRef, &publicKeyRef, &privateKeyRef);
    
    if (status == errSecSuccess) {
        status = savePubKeyFromRef(keyType,publicKeyRef);
        CFRelease(publicKeyRef);
        CFRelease(privateKeyRef);
    }
    
    if (error != NULL) {
        CFRelease(error);
    }
    CFRelease(accessControlDict);
    CFRelease(generatePairRef);

    return status;
}

/**
 查询公钥
 
 @return 公钥信息
 */
OSStatus dv_queryPubKeyRef(CFStringRef keyType,SecKeyRef *publicKeyRef)
{
    CFMutableDictionaryRef getPublicKeyQuery = newCFDict;
    CFDictionarySetValue(getPublicKeyQuery, kSecClass,                kSecClassKey);
    CFDictionarySetValue(getPublicKeyQuery, kSecAttrKeyType,          keyType);
    CFDictionarySetValue(getPublicKeyQuery, kSecAttrApplicationTag,   dv_pubKeyName);
    CFDictionarySetValue(getPublicKeyQuery, kSecAttrKeyClass,         kSecAttrKeyClassPublic);
    CFDictionarySetValue(getPublicKeyQuery, kSecReturnRef,           kCFBooleanTrue);
    //是否需要返回完整内容（如果返回的是完整内容，即返回的是字典，字典中的kSecValueRef才是公钥。如不是的话，直接返回公钥）
    CFDictionarySetValue(getPublicKeyQuery, kSecReturnPersistentRef,  kCFBooleanFalse);
    
    OSStatus status = SecItemCopyMatching(getPublicKeyQuery, (CFTypeRef *)publicKeyRef);

    CFRelease(getPublicKeyQuery);
    return status;
}

/**
 查询私钥
 @params privateKeyRef 输出参数 私钥信息
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_queryPriKeyRef(SecKeyRef *privateKeyRef)
{
    CFMutableDictionaryRef getPrivateKeyRef = newCFDict;
    CFDictionarySetValue(getPrivateKeyRef, kSecClass, kSecClassKey);
    CFDictionarySetValue(getPrivateKeyRef, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(getPrivateKeyRef, kSecAttrLabel, dv_priKeyName);
    CFDictionarySetValue(getPrivateKeyRef, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(getPrivateKeyRef, kSecUseOperationPrompt, CFSTR("Authenticate to sign data"));
    
    
    OSStatus status =  SecItemCopyMatching(getPrivateKeyRef, (CFTypeRef *)privateKeyRef);
    CFRelease(getPrivateKeyRef);
    return status;
}

/**
 删除公钥
 @params keyType
             kSecAttrKeyTypeRSA -- 2048
             kSecAttrKeyTypeEC -- 256
             kSecAttrKeyTypeECSECPrimeRandom -- 2048
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_deletePubKey(CFStringRef keyType)
{
    CFMutableDictionaryRef savePublicKeyDict = newCFDict;
    CFDictionaryAddValue(savePublicKeyDict, kSecClass,        kSecClassKey);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrKeyType,  keyType);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrApplicationTag, dv_pubKeyName);
    
    OSStatus err = SecItemDelete(savePublicKeyDict);
    while (err == errSecDuplicateItem)
    {
        err = SecItemDelete(savePublicKeyDict);
    }
    CFRelease(savePublicKeyDict);
    return err;
}

/**
 删除私钥
 
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_deletePriKey(void)
{
    CFMutableDictionaryRef getPrivateKeyRef = newCFDict;
    CFDictionarySetValue(getPrivateKeyRef, kSecClass, kSecClassKey);
    CFDictionarySetValue(getPrivateKeyRef, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(getPrivateKeyRef, kSecAttrLabel, dv_priKeyName);
    CFDictionarySetValue(getPrivateKeyRef, kSecReturnRef, kCFBooleanTrue);
    
    OSStatus err = SecItemDelete(getPrivateKeyRef);
    while (err == errSecDuplicateItem)
    {
        err = SecItemDelete(getPrivateKeyRef);
    }
    CFRelease(getPrivateKeyRef);
    return err;
}

/**
 使用私钥对摘要信息签名
 
 @param digestData 摘要信息
 @param digestLength 摘要信息长度
 @param padding SecPadding
 @param outData 输出签名后的数据
 @param outDataLen 输出签名后的数据长度
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_priKeySignData(char * digestData,size_t digestLength,SecPadding padding,char *outData,size_t *outDataLen)
{
    //char*直接强转成uint8_t
//    uint8_t signature[256] = { 0 };
//    size_t signatureLength = sizeof(signature);
    
    SecKeyRef privateKeyRef;
    dv_queryPriKeyRef(&privateKeyRef);
    
    return SecKeyRawSign(privateKeyRef, padding, (const uint8_t *)digestData, digestLength, (uint8_t *)outData, outDataLen);
}


/**
 使用公钥验证摘要信息签名
 
 @param digestData 摘要信息（hash计算过后的数据）
 @param digestLength 摘要信息长度
 @param padding 填充方式
         三种填充方式区别：
         kSecPaddingNone      = 0,   要加密的数据块大小<＝SecKeyGetBlockSize的大小，如这里是128的话
         kSecPaddingPKCS1     = 1,   要加密的数据块大小<=128-11
         kSecPaddingOAEP      = 2,   要加密的数据块大小<=128-42
 @param sig 用私钥签名得出来的信息（即dv_privateKeySignData方法中的outData）
 @param sigLen 用私钥签名得出来的信息的长度
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_pubKeyVerifySign(CFStringRef keyType,char *digestData,size_t digestLength,SecPadding padding,char *sig,size_t sigLen)
{
    SecKeyRef publicKeyRef;
    dv_queryPubKeyRef(keyType,&publicKeyRef);
    return SecKeyRawVerify(publicKeyRef, padding, (const uint8_t * const )digestData, digestLength, (const uint8_t *)sig, sigLen);
}

/**
 使用公钥加密（其中SecKeyRef的kSecAttrKeyType为kSecAttrKeyTypeRSA才能成功）
 
 @param key 公钥
 @param padding 填充方式，同上
 @param plainText 需要加密的内容
 @param plainTextLen 需要加密的内容长度
 @param cipherText 输出加密后的内容（请确保创建的空间足够）
 @param cipherTextLen 输出加密后的内容长度
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_pubKeyEncrypt(
                          SecKeyRef           key,
                          SecPadding          padding,
                          char *              plainText,
                          size_t              plainTextLen,
                          char *              cipherText,
                          size_t              *cipherTextLen)
{
    //需要加密数据
    const uint8_t *srcbuf = (const uint8_t *)plainText;
    //需要加密数据的总长度
    size_t srclen = plainTextLen;
    //获取密钥block大小（每次加密大小最大只能是block大小）
    size_t block_size = SecKeyGetBlockSize(key) * sizeof(uint8_t);
    //创建临时变量存储每次加密数据，创建大小为block大小
    void *outbuf = malloc(block_size);

    for (int idx=0; idx<srclen; idx+=block_size) {
        //每次取一段block大小数据
        size_t data_len = srclen - idx;
        if(data_len > block_size){
            data_len = block_size;
        }
        size_t outlen = block_size;
        OSStatus status = errSecSuccess;
        //加密
        status = SecKeyEncrypt(key,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            printf("SecKeyEncrypt fail. Error Code: %d", status);
            return status;
        }else{
            //把每次分段加密的数据拼接到输出参数
            memcpy(cipherText+*cipherTextLen, outbuf, outlen);
            *cipherTextLen += outlen;
        }
    }
    return errSecSuccess;
}

/**
 私钥解密数据
 
 @param key 私钥
 @param padding 填充方式，同上
 @param cipherText 需要解密的内容
 @param cipherTextLen 需要解密的内容长度
 @param plainText 输出解密后内容
 @param plainTextLen 输出解密后内容长度
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_priKeyDecrypt(
                          SecKeyRef           key,                /* Private key */
                          SecPadding          padding,            /* kSecPaddingNone,
                                                                   kSecPaddingPKCS1,
                                                                   kSecPaddingOAEP */
                          char *              cipherText,
                          size_t              cipherTextLen,        /* length of cipherText */
                          char *              plainText,
                          size_t              *plainTextLen)        /* IN/OUT */
{
    //需要加密数据
    const uint8_t *srcbuf = (const uint8_t *)cipherText;
    //需要加密数据的总长度
    size_t srclen = cipherTextLen;
    //获取密钥block大小（每次解密大小最大只能是block大小）
    size_t block_size = SecKeyGetBlockSize(key) * sizeof(uint8_t);
    //创建临时变量存储每次加密数据，创建大小为block大小
    UInt8 *outbuf = malloc(block_size);

    for(int idx=0; idx<srclen; idx+=block_size){
        //每次取一段block大小数据
        size_t data_len = srclen - idx;
        if(data_len > block_size){
            data_len = block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        //解密
        status = SecKeyDecrypt(key,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            printf("SecKeyEncrypt fail. Error Code: %d", status);
            return status;
        }else{
            //the actual decrypted data is in the middle, locate it!
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            memcpy(plainText + *plainTextLen, &outbuf[idxFirstZero+1], idxNextZero-idxFirstZero-1);
            *plainTextLen += (idxNextZero-idxFirstZero-1);
        }
    }
    
    free(outbuf);
    CFRelease(key);
    return errSecSuccess;
}
