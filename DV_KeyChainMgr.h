//
//  DV_KeyChainMgr.h
//  基于Security库的KeyChain的C实现（简单实现）
// 
//  Created by Devil on 2019/3/18.
//  Copyright © 2019 Devil. All rights reserved.
//

#ifndef DV_KeyChainMgr_h
#define DV_KeyChainMgr_h

#include <stdio.h>
#include <Security/Security.h>

//默认的account信息(普通keychain存储数据使用)
extern CFStringRef dv_accountStringRef;
//访问控制(默认为kSecAccessControlUserPresence)
extern CFOptionFlags dv_secAccessControl;


//需要使用公私钥时使用
//默认的公私钥名称(key -- 用于增删改查时使用)
extern CFStringRef dv_keyPairName;

//CFStringRef secClass 有以下几个值：此类默认使用kSecClassGenericPassword

//kSecClassGenericPassword(通用密码) -- 下面是包含的属性 （kSecAttrAccessControl需要在添加Item时加入）
//    https://developer.apple.com/documentation/security/ksecclassgenericpassword
//    kSecAttrAccess (macOS only)
//    kSecAttrAccessControl 其在访问控制实例中的值指示该项的访问控制设置。
//    kSecAttrAccessGroup (iOS; also macOS if kSecAttrSynchronizable specified)
//    kSecAttrAccessible (iOS; also macOS if kSecAttrSynchronizable specified)
//    kSecAttrCreationDate 值指示项的创建日期的键
//    kSecAttrModificationDate 其值指示项的最后修改日期
//    kSecAttrDescription 值为指示项说明的字符串的键
//    kSecAttrComment 其值是一个字符串，表示与该项关联的注释
//    kSecAttrCreator 其值表示项目的创建者
//    kSecAttrType 其值表示项目的类型
//    kSecAttrLabel 其值是表示项目标签的字符串
//    kSecAttrIsInvisible 其值为布尔值，表示项目的可见性
//    kSecAttrIsNegative 其值为布尔值，指示该项是否具有有效密码
//    kSecAttrAccount 其值是表示项目帐户名称的字符串
//    kSecAttrService 其值是表示项目服务的字符串
//    kSecAttrGeneric 其值表示项目的用户定义属性
//    kSecAttrSynchronizable 其值是一个字符串，指示该项是否通过iCloud同步。

//kSecClassInternetPassword(互联网密码) -- 下面是包含的属性
//    https://developer.apple.com/documentation/security/ksecclassinternetpassword
//    kSecAttrAccess (macOS only) 其访问实例中的值指示此项的访问控制列表设置。
//    kSecAttrAccessGroup (iOS; also macOS if kSecAttrSynchronizable specified)
//    kSecAttrAccessible (iOS; also macOS if kSecAttrSynchronizable specified)
//    kSecAttrCreationDate 值指示项的创建日期的键
//    kSecAttrModificationDate 其值指示项的最后修改日期
//    kSecAttrDescription 值为指示项说明的字符串的键
//    kSecAttrComment 其值是一个字符串，表示与该项关联的注释
//    kSecAttrCreator 其值表示项目的创建者
//    kSecAttrType 其值表示项目的类型
//    kSecAttrLabel 其值是表示项目标签的字符串
//    kSecAttrIsInvisible 其值为布尔值，表示项目的可见性
//    kSecAttrIsNegative 其值为布尔值，指示该项是否具有有效密码
//    kSecAttrAccount 其值是表示项目帐户名称的字符串
//    kSecAttrSecurityDomain 对应的值为CFString类型，表示Internet安全域。
//    kSecAttrServer 其值是表示项目服务的字符串
//    kSecAttrProtocol 其值表示项目的协议
//    kSecAttrAuthenticationType 其值表示项目的身份验证方案
//    kSecAttrPort 其值表示项目的端口
//    kSecAttrPath 其值是一个表示项目路径属性的字符串
//    kSecAttrSynchronizable 其值是一个字符串，指示该项是否通过iCloud同步。

//kSecClassCertificate(证书) -- 下面是包含的属性
//    https://developer.apple.com/documentation/security/ksecclasscertificate
//    kSecAttrAccess (macOS only) 其访问实例中的值指示此项的访问控制列表设置。
//    kSecAttrAccessGroup (iOS only) 其值是一个字符串，指示项所在的访问组。
//    kSecAttrAccessible (iOS only) 其值指示何时可以访问键链项。
//    kSecAttrCertificateType 表示证书类型（请参阅cssmtype.h中的CSSM_CERT_TYPE枚举）
//    kSecAttrCertificateEncoding 其值表示项目的证书编码
//    kSecAttrLabel 其值是表示项目标签的字符串
//    kSecAttrSubject 其值表示项目的主题名称
//    kSecAttrIssuer 其值表示项目的发行者
//    kSecAttrSerialNumber 其值表示项目的序列号
//    kSecAttrSubjectKeyID 其值表示项目的主题密钥ID
//    kSecAttrPublicKeyHash 其值表示项目的公钥哈希

//kSecClassKey(密钥) -- 下面是包含的属性
//    https://developer.apple.com/documentation/security/ksecclasskey
//    kSecAttrAccess (macOS only) 其访问实例中的值指示此项的访问控制列表设置。
//    kSecAttrAccessGroup (iOS only) 其值是一个字符串，指示项所在的访问组。
//    kSecAttrAccessible (iOS only) 其值指示何时可以访问键链项。
//    kSecAttrKeyClass 对应的值是CFTypeRef类型，并指定一种加密密钥。 键类值中列出了可能的值。 只读。
//    kSecAttrLabel 其值是表示项目标签的字符串
//    kSecAttrApplicationLabel 其值表示项目的应用程序标签
//    kSecAttrIsPermanent 其值表示项目的持久性
//    kSecAttrApplicationTag 其值表示项目的私有标记
//    kSecAttrKeyType 其值表示项目的算法
//    kSecAttrPRF 其值表示项目的伪随机函数
//    kSecAttrSalt 其值表示用于此项目的盐
//    kSecAttrRounds 其值表示运行伪随机函数的轮数
//    kSecAttrKeySizeInBits 一个密钥，其值表示加密密钥中的位数。
//    kSecAttrEffectiveKeySize 其值表示加密密钥中的有效位数
//    kSecAttrCanEncrypt 相应的值为CFBoolean类型，指示此加密密钥是否可用于加密数据。在密钥创建时，如果未明确指定，则此属性默认为私钥的                    kCFBooleanFalse和公钥的kCFBooleanTrue
//    kSecAttrCanDecrypt 其值为布尔值，表示加密密钥是否可用于解密。如果没有明确指定，则此属性默认为私钥的kCFBooleanTrue和公钥的kCFBooleanFalse。
//    kSecAttrCanDerive 其值为布尔值，表示加密密钥是否可用于派生
//    kSecAttrCanSign 其值为布尔值，表示加密密钥是否可用于数字签名。
//    kSecAttrCanVerify 其值为布尔值，表示加密密钥是否可用于签名验证
//    kSecAttrCanWrap 其值为布尔值，表示加密密钥是否可用于换行
//    kSecAttrCanUnwrap 其值为布尔值，表示加密密钥是否可用于展开

//kSecClassIdentity(身份)
//    https://developer.apple.com/documentation/security/ksecclassidentity
//    An identity is a certificate paired with its associated private key. Because an identity is the combination of a private key and a certificate, this class shares attributes of both kSecClassKey and kSecClassCertificate.
//    拥有kSecClassKey 和 kSecClassCertificate所有属性

#pragma mark- 属性
//键
//CFTypeRef kSecAttrAccessible;                                        //可访问性 类型透明
//值
//          CFTypeRef kSecAttrAccessibleWhenUnlocked;                  //解锁可访问，备份
//          CFTypeRef kSecAttrAccessibleAfterFirstUnlock;              //第一次解锁后可访问，备份
//          CFTypeRef kSecAttrAccessibleAlways;                        //一直可访问，备份
//          CFTypeRef kSecAttrAccessibleWhenUnlockedThisDeviceOnly;    //解锁可访问，不备份
//          CFTypeRef kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;//第一次解锁后可访问，不备份
//          CFTypeRef kSecAttrAccessibleAlwaysThisDeviceOnly;          //一直可访问，不备份
//键
//CFTypeRef kSecAttrAccessControl //其在访问控制实例中的值指示该项的访问控制设置。
//值
//    kSecAccessControlUserPresence item通过锁屏密码或者Touch ID进行验证，Touch ID可以不设置，增加或者移除手指都能使用item。
//    kSecAccessControlTouchIDAny item只能通过Touch ID验证，Touch ID 必须设置，增加或移除手指都能使用item。
//    kSecAccessControlTouchIDCurrentSet item只能通过Touch ID进行验证，增加或者移除手指，item将被删除。
//    kSecAccessControlDevicePasscode item通过锁屏密码验证访问。
//    kSecAccessControlOr 如果设置多个flag，只要有一个满足就可以。
//    kSecAccessControlAnd 如果设置多个flag，必须所有的都满足才行。
//    kSecAccessControlPrivateKeyUsage 私钥签名操作
//    kSecAccessControlApplicationPassword 额外的item密码，可以让用户自己设置一个访问密码，这样只有知道密码才能访问。

//CFTypeRef kSecAttrCreationDate;      //创建日期          CFDateRef
//CFTypeRef kSecAttrModificationDate;  //最后一次修改日期   CFDateRef
//CFTypeRef kSecAttrDescription;       //描述             CFStringRef
//CFTypeRef kSecAttrComment;           //注释             CFStringRef
//CFTypeRef kSecAttrCreator;           //创建者            CFNumberRef(4字符，如'aLXY')
//CFTypeRef kSecAttrType;              //类型             CFNumberRef(4字符，如'aTyp')
//CFTypeRef kSecAttrLabel;             //标签(给用户看)     CFStringRef
//CFTypeRef kSecAttrIsInvisible;       //是否隐藏          CFBooleanRef(kCFBooleanTrue,kCFBooleanFalse)
//CFTypeRef kSecAttrIsNegative;        //是否具有密码       CFBooleanRef(kCFBooleanTrue,kCFBooleanFalse)此项表示当前的item是否只是一个占位项，或者说是只有key没有value。
//CFTypeRef kSecAttrAccount;           //账户名            CFStringRef
//CFTypeRef kSecAttrService;           //所具有服务         CFStringRef
//CFTypeRef kSecAttrGeneric;           //用户自定义内容      CFDataRef
//CFTypeRef kSecAttrSecurityDomain;    //网络安全域         CFStringRef
//CFTypeRef kSecAttrServer;            //服务器域名或IP地址  CFStringRef

//键
//CFTypeRef kSecAttrProtocol;                      //协议类型 CFNumberRef
//          值
//          CFTypeRef kSecAttrProtocolFTP;         //
//          CFTypeRef kSecAttrProtocolFTPAccount;  //
//          CFTypeRef kSecAttrProtocolHTTP;        //
//          CFTypeRef kSecAttrProtocolIRC;         //
//          CFTypeRef kSecAttrProtocolNNTP;        //
//          CFTypeRef kSecAttrProtocolPOP3;        //
//          CFTypeRef kSecAttrProtocolSMTP;        //
//          CFTypeRef kSecAttrProtocolSOCKS;       //
//          CFTypeRef kSecAttrProtocolIMAP;        //
//          CFTypeRef kSecAttrProtocolLDAP;        //
//          CFTypeRef kSecAttrProtocolAppleTalk;   //
//          CFTypeRef kSecAttrProtocolAFP;         //
//          CFTypeRef kSecAttrProtocolTelnet;      //
//          CFTypeRef kSecAttrProtocolSSH;         //
//          CFTypeRef kSecAttrProtocolFTPS;        //
//          CFTypeRef kSecAttrProtocolHTTPS;       //
//          CFTypeRef kSecAttrProtocolHTTPProxy;   //
//          CFTypeRef kSecAttrProtocolHTTPSProxy;  //
//          CFTypeRef kSecAttrProtocolFTPProxy;    //
//          CFTypeRef kSecAttrProtocolSMB;         //
//          CFTypeRef kSecAttrProtocolRTSP;        //
//          CFTypeRef kSecAttrProtocolRTSPProxy;   //
//          CFTypeRef kSecAttrProtocolDAAP;        //
//          CFTypeRef kSecAttrProtocolEPPC;        //
//          CFTypeRef kSecAttrProtocolIPP;         //
//          CFTypeRef kSecAttrProtocolNNTPS;       //
//          CFTypeRef kSecAttrProtocolLDAPS;       //
//          CFTypeRef kSecAttrProtocolTelnetS;     //
//          CFTypeRef kSecAttrProtocolIMAPS;       //
//          CFTypeRef kSecAttrProtocolIRCS;        //
//          CFTypeRef kSecAttrProtocolPOP3S;       //

//键
//CFTypeRef kSecAttrAuthenticationType;                      //认证类型 CFNumberRef
//          值
//          CFTypeRef kSecAttrAuthenticationTypeNTLM;        //
//          CFTypeRef kSecAttrAuthenticationTypeMSN;         //
//          CFTypeRef kSecAttrAuthenticationTypeDPA;         //
//          CFTypeRef kSecAttrAuthenticationTypeRPA;         //
//          CFTypeRef kSecAttrAuthenticationTypeHTTPBasic;   //
//          CFTypeRef kSecAttrAuthenticationTypeHTTPDigest;  //
//          CFTypeRef kSecAttrAuthenticationTypeHTMLForm;    //
//          CFTypeRef kSecAttrAuthenticationTypeDefault;     //

//CFTypeRef kSecAttrPort;                 //网络端口           CFNumberRef
//CFTypeRef kSecAttrPath;                 //访问路径           CFStringRef
//CFTypeRef kSecAttrSubject;              //X.500主题名称      CFDataRef
//CFTypeRef kSecAttrIssuer;               //X.500发行者名称     CFDataRef
//CFTypeRef kSecAttrSerialNumber;         //序列号             CFDataRef
//CFTypeRef kSecAttrSubjectKeyID;         //主题ID             CFDataRef
//CFTypeRef kSecAttrPublicKeyHash;        //公钥Hash值         CFDataRef
//CFTypeRef kSecAttrCertificateType;      //证书类型            CFNumberRef
//CFTypeRef kSecAttrCertificateEncoding;  //证书编码类型        CFNumberRef

//CFTypeRef kSecAttrKeyClass;                     //加密密钥类  CFTypeRef
//          值
//          CFTypeRef kSecAttrKeyClassPublic;     //公钥
//          CFTypeRef kSecAttrKeyClassPrivate;    //私钥
//          CFTypeRef kSecAttrKeyClassSymmetric;  //对称密钥

//CFTypeRef kSecAttrApplicationLabel;  //标签(给程序使用)          CFStringRef(通常是公钥的Hash值)
//CFTypeRef kSecAttrIsPermanent;       //是否永久保存加密密钥       CFBooleanRef
//CFTypeRef kSecAttrApplicationTag;    //标签(私有标签数据)         CFDataRef

//CFTypeRef kSecAttrKeyType;  //加密密钥类型(算法)   CFNumberRef
//          值
//        extern const CFTypeRef kSecAttrKeyTypeRSA;
//        @constant kSecAttrKeyTypeECSECPrimeRandom.
//        @constant kSecAttrKeyTypeEC This is the legacy name for kSecAttrKeyTypeECSECPrimeRandom, new applications should not use it.
//        @constant kSecAttrKeyTypeDSA (OSX only)
//        @constant kSecAttrKeyTypeAES (OSX only)
//        @constant kSecAttrKeyType3DES (OSX only)
//        @constant kSecAttrKeyTypeRC4 (OSX only)
//        @constant kSecAttrKeyTypeRC2 (OSX only)
//        @constant kSecAttrKeyTypeCAST (OSX only)
//        @constant kSecAttrKeyTypeECDSA (deprecated; use kSecAttrKeyTypeEC instead.) (OSX only)

//CFTypeRef kSecAttrKeySizeInBits;     //密钥总位数               CFNumberRef
//CFTypeRef kSecAttrEffectiveKeySize;  //密钥有效位数              CFNumberRef
//CFTypeRef kSecAttrCanEncrypt;        //密钥是否可用于加密         CFBooleanRef
//CFTypeRef kSecAttrCanDecrypt;        //密钥是否可用于解密         CFBooleanRef
//CFTypeRef kSecAttrCanDerive;         //密钥是否可用于导出其他密钥   CFBooleanRef
//CFTypeRef kSecAttrCanSign;           //密钥是否可用于数字签名      CFBooleanRef
//CFTypeRef kSecAttrCanVerify;         //密钥是否可用于验证数字签名   CFBooleanRef
//CFTypeRef kSecAttrCanWrap;           //密钥是否可用于打包其他密钥   CFBooleanRef
//CFTypeRef kSecAttrCanUnwrap;         //密钥是否可用于解包其他密钥   CFBooleanRef
//CFTypeRef kSecAttrAccessGroup;       //访问组                   CFStringRef


#pragma mark- 搜索
//CFTypeRef kSecMatchPolicy;                 //指定策略            SecPolicyRef
//CFTypeRef kSecMatchItemList;               //指定搜索范围         CFArrayRef(SecKeychainItemRef, SecKeyRef, SecCertificateRef, SecIdentityRef,CFDataRef)数组内的类型必须唯一。仍然会搜索钥匙串，但是搜索结果需要与该数组取交集作为最终结果。
//CFTypeRef kSecMatchSearchList;             //
//CFTypeRef kSecMatchIssuers;                //指定发行人数组       CFArrayRef
//CFTypeRef kSecMatchEmailAddressIfPresent;  //指定邮件地址         CFStringRef
//CFTypeRef kSecMatchSubjectContains;        //指定主题            CFStringRef
//CFTypeRef kSecMatchCaseInsensitive;        //指定是否不区分大小写  CFBooleanRef(kCFBooleanFalse或不提供此参数,区分大小写;kCFBooleanTrue,不区分大小写)
//CFTypeRef kSecMatchTrustedOnly;            //指定只搜索可信证书    CFBooleanRef(kCFBooleanFalse或不提供此参数,全部证书;kCFBooleanTrue,只搜索可信证书)
//CFTypeRef kSecMatchValidOnDate;            //指定有效日期         CFDateRef(kCFNull表示今天)
//CFTypeRef kSecMatchLimit;                  //指定结果数量         CFNumberRef(kSecMatchLimitOne;kSecMatchLimitAll)
//CFTypeRef kSecMatchLimitOne;               //首条结果
//CFTypeRef kSecMatchLimitAll;               //全部结果


#pragma mark- 列表
//CFTypeRef kSecUseItemList;   //CFArrayRef(SecKeychainItemRef, SecKeyRef, SecCertificateRef, SecIdentityRef,CFDataRef)数组内的类型必须唯一。用户提供用于查询的列表。当这个列表被提供的时候，不会再搜索钥匙串。


#pragma mark- 返回值类型
//可以同时指定多种返回值类型
//CFTypeRef kSecReturnData;           //返回数据(CFDataRef)                  CFBooleanRef
//CFTypeRef kSecReturnAttributes;     //返回属性字典(CFDictionaryRef)         CFBooleanRef
//CFTypeRef kSecReturnRef;            //返回实例(SecKeychainItemRef, SecKeyRef, SecCertificateRef, SecIdentityRef, or CFDataRef)         CFBooleanRef
//CFTypeRef kSecReturnPersistentRef;  //返回持久型实例(CFDataRef)             CFBooleanRef


#pragma mark- 写入值类型
//CFTypeRef kSecValueData;
//CFTypeRef kSecValueRef;
//CFTypeRef kSecValuePersistentRef;


/**
 设置新的account值（设置后本次app运行期间一直使用此值）
 @param ref 新的account值
 */
void dv_setAccountStringRef(CFStringRef ref);

/**
 设置新的SecAccessControl值（设置后本次app运行期间一直使用此值）(默认为kSecAccessControlUserPresence)
 @param flag 新的SecAccessControl值
 */
void dv_setSecAccessControl(CFOptionFlags flag);

/**
 设置新的dv_keyPairName值（设置后本次app运行期间一直使用此值）
 @param name 新的dv_keyPairName值
 */
void dv_setKeyPairName(char *name);

/**
  初始化所有变量(首次使用无需调用，只有在调用下面释放方法后，再次使用需先调用此方法)
 */
void dv_initAllVariable(void);

/**
 释放所有变量
 */
void dv_freeAllVariable(void);

/**
 增加KeyChain键值对
 @param key 键
 @param value 值
 @param isNeedAccessControl 是否需要访问控制
 @return OSStatus == errSecSuccess成功，其它失败
 */
OSStatus dv_keyChainAdd(CFStringRef key,CFDataRef value,CFBooleanRef isNeedAccessControl);

/**
 查询KeyChain键值对
 @param key 键
 @param isNeedReturnData 是否需要返回查询的数据
 @return 需要返回数据时，返回的是查询到的数据，并且需要调用者自己释放(CFRelease(ref))。不需要返回数据时，返回kCFBooleanTrue(查询成功)或者kCFBooleanFalse(查询失败)
 */
CFTypeRef dv_keyChainQuery(CFStringRef key,CFBooleanRef isNeedReturnData);

/**
 修改KeyChain键值对
 @param key 需要修改的键
 @param value 新的值
 @return OSStatus == errSecSuccess成功，其它失败
 */
OSStatus dv_keyChainUpdate(CFStringRef key,CFDataRef value);

/**
 删除KeyChain键值对
 @param key 需要删除的键
 @return OSStatus == errSecSuccess成功，其它失败
 */
OSStatus dv_keyChainDelete(CFStringRef key);


/**
 生成公私钥 Secure Enclave
 @params keyType
            kSecAttrKeyTypeRSA -- 2048
            kSecAttrKeyTypeEC -- 256
            kSecAttrKeyTypeECSECPrimeRandom -- 2048
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_secKeyGeneratePair(CFStringRef keyType);


/**
 查询公钥
 @params keyType
             kSecAttrKeyTypeRSA -- 2048
             kSecAttrKeyTypeEC -- 256
             kSecAttrKeyTypeECSECPrimeRandom -- 2048
 @params publicKeyRef 输出参数 公钥信息
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_queryPubKeyRef(CFStringRef keyType,SecKeyRef *publicKeyRef);

/**
 查询私钥
 @params privateKeyRef 输出参数 私钥信息
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_queryPriKeyRef(SecKeyRef *privateKeyRef);

/**
 删除公钥
 @params keyType
             kSecAttrKeyTypeRSA -- 2048
             kSecAttrKeyTypeEC -- 256
             kSecAttrKeyTypeECSECPrimeRandom -- 2048
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_deletePubKey(CFStringRef keyType);

/**
 删除私钥
 
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_deletePriKey(void);


/**
 使用私钥对摘要信息签名

 @param digestData 摘要信息（hash计算过后的数据，可由char*直接强转成uint8_t）
 @param digestLength 摘要信息长度
 @param padding 填充方式
        三种填充方式区别：
         kSecPaddingNone      = 0,   要加密的数据块大小<＝SecKeyGetBlockSize的大小，如这里是128的话
         kSecPaddingPKCS1     = 1,   要加密的数据块大小<=128-11
         kSecPaddingOAEP      = 2,   要加密的数据块大小<=128-42
 @param outData 输出签名后的数据(uint8_t outData[256] = { 0 };) --> outData转成OC的NSData：[NSData dataWithBytes:outData length:outDataLen]
 @param outDataLen 输出签名后的数据长度
 @return errSecSuccess成功 其它失败
 */
OSStatus dv_priKeySignData(char *digestData,size_t digestLength,SecPadding padding,char *outData,size_t *outDataLen);


/**
 使用公钥验证摘要信息签名

 @param digestData 摘要信息（RSA算法的仅支持最大256字节数据，因为创建的RSA是2048位的，ECC算法的暂时未发现限制是多少，但数据太大会奔溃。最好拿hash运算过后的数据）
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
OSStatus dv_pubKeyVerifySign(
                             CFStringRef keyType,
                             char * digestData,
                             size_t digestLength,
                             SecPadding padding,
                             char *sig,
                             size_t sigLen);


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
                          size_t              *cipherTextLen);


/**
 私钥解密数据

 @param key 私钥
 @param padding 填充方式，同上
 @param cipherText 需要解密的内容
 @param cipherTextLen 需要解密的内容长度
 @param plainText 输出解密后内容（请确保创建的空间足够）
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
                          size_t              *plainTextLen);        /* IN/OUT */

#endif /* DV_KeyChainMgr_h */
