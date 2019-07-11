//
//  NSObject+KeyChainHelper.m
//
//  Created by Devil on 2019/3/18.
//  Copyright © 2019 Devil. All rights reserved.
//

#import "NSObject+KeyChainHelper.h"
#import "DV_KeyChainMgr.h"
#import "KeyInterface.h"
@implementation NSObject (KeyChainHelper)
/**
 keyChain查询
 
 @param key 键
 @param result 查询结果回调
 */
-(void) dv_keyChainQueryWithKey:(NSString *)key result:(void(^)(NSString *resultStr))result
{
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        CFDataRef ref = dv_keyChainQuery((__bridge CFStringRef)key , kCFBooleanTrue);
        NSString *queryResultStr = nil;
        if (ref) {
            NSData *data = (__bridge NSData *)ref;
            queryResultStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            result(queryResultStr);
            if (ref != NULL) {
                CFRelease(ref);
            }
        });
    });
    
    
}

/**
 keyChain添加值
 
 @param key 键
 @param value 值
 @param isNeedAccessControl 是否需要访问控制
 @param result 结果回调 -- 是否成功(OSStatus等于errSecSuccess为成功)
 */
-(void) dv_keyChainAddWithKey:(NSString *)key value:(NSString *)value isNeedAccessControl:(BOOL)isNeedAccessControl result:(void(^)(OSStatus resultStatus))result
{
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
        OSStatus status = dv_keyChainAdd((__bridge CFStringRef)key, (__bridge CFDataRef)data,isNeedAccessControl?kCFBooleanTrue:kCFBooleanFalse);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (status == errSecSuccess) {
                NSLog(@"添加成功");
            }else{
                NSLog(@"添加失败");
            }
            result(status);
        });
    });

}


/**
 keyChain修改值
 
 @param key 键
 @param value 新值
 @param result 结果回调 -- 是否成功(OSStatus等于errSecSuccess为成功)
 */
-(void) dv_keyChainUpdateWithKey:(NSString *)key value:(NSString *)value result:(void(^)(OSStatus resultStatus))result
{
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
        OSStatus status = dv_keyChainUpdate((__bridge CFStringRef)key, (__bridge CFDataRef)data);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (status == errSecSuccess) {
                NSLog(@"修改成功");
            }else{
                NSLog(@"修改失败");
            }
            result(status);
        });
    });
    
}

/**
 keyChain删除值
 
 @param key 键
 @param result 结果回调 -- 是否成功(OSStatus等于errSecSuccess为成功)
 */
-(void) dv_keyChainDeleteWithKey:(NSString *)key result:(void(^)(OSStatus resultStatus))result
{
    
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        OSStatus status = dv_keyChainDelete((__bridge CFStringRef)key);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (status == errSecSuccess) {
                NSLog(@"删除成功");
            }else{
                NSLog(@"删除失败");
            }
            result(status);
        });
    });
}


//产生密钥
- (CFMutableDictionaryRef)generateKeyAsync:(void(^)(SecKeyRef ref))callBack {
    
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject;
    
    //设置ACL，使用kSecAccessControlTouchIDAny表示使用Touch ID来保护密钥。
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenUnlocked,
                                                kSecAccessControlTouchIDAny, &error);
    
    NSDictionary *parameters = @{
//                                 (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,//表示使用SecureEnclave来保存密钥
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,//表示产生ECC密钥对，注意目前只支持256位的ECC算法
                                 (__bridge id)kSecAttrKeySizeInBits: @2048,
                                 (__bridge id)kSecPrivateKeyAttrs: @{
                                         (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                                         (__bridge id)kSecAttrIsPermanent: @YES,
                                         (__bridge id)kSecAttrLabel: @"my-se-key",
                                         },
                                 };
    SecKeyRef publicKey, privateKey;
    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
    CFMutableDictionaryRef dic = CFDictionaryCreateMutable(kCFAllocatorDefault, 2, NULL, NULL);
    CFDictionarySetValue(dic, "pri", privateKey);
    CFDictionarySetValue(dic, "pub", publicKey);
    return dic;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        SecKeyRef publicKey, privateKey;
        OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
        if (status == errSecSuccess) {
            NSLog(@"产生密码成功");
            
            //这里先把公钥保存到keychain才能拿到真正的公钥数据
            NSDictionary *pubDict = @{
                                      (__bridge id)kSecClass              : (__bridge id)kSecClassKey,
                                      (__bridge id)kSecAttrKeyType        : (__bridge id)kSecAttrKeyTypeRSA,
                                      (__bridge id)kSecAttrLabel          : @"",
                                      (__bridge id)kSecAttrIsPermanent    : @(YES),
                                      (__bridge id)kSecValueRef           : (__bridge id)publicKey,
                                      (__bridge id)kSecAttrKeyClass       : (__bridge id)kSecAttrKeyClassPublic,
                                      (__bridge id)kSecReturnData         : @(YES)
                                      };
            
            CFTypeRef dataRef = NULL;
            status = SecItemAdd((__bridge CFDictionaryRef)pubDict, &dataRef);
            if(status == errSecSuccess){
                NSLog(@"导出公钥成功");
                dispatch_async(dispatch_get_main_queue(), ^{
                    callBack(publicKey);
                });
            }else{
                NSLog(@"导出公钥失败");
            }
            
            CFRelease(dataRef);
            CFRelease(privateKey);
            CFRelease(publicKey);
        }else{
            NSLog(@"产生密码失败");
        }
    });
}


@end
