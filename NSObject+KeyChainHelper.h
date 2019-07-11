//
//  NSObject+KeyChainHelper.h
//
//  Created by Devil on 2019/3/18.
//  Copyright © 2019 Devil. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSObject (KeyChainHelper)

/**
 keyChain查询

 @param key 键
 @param result 查询结果回调
 */
-(void) dv_keyChainQueryWithKey:(NSString *)key result:(void(^)(NSString *resultStr))result;


/**
 keyChain添加值

 @param key 键
 @param value 值
 @param isNeedAccessControl 是否需要访问控制
 @param result 结果回调 -- 是否成功(OSStatus等于errSecSuccess为成功)
 */
-(void) dv_keyChainAddWithKey:(NSString *)key value:(NSString *)value isNeedAccessControl:(BOOL)isNeedAccessControl result:(void(^)(OSStatus resultStatus))result;


/**
 keyChain修改值

 @param key 键
 @param value 新值
 @param result 结果回调 -- 是否成功(OSStatus等于errSecSuccess为成功)
 */
-(void) dv_keyChainUpdateWithKey:(NSString *)key value:(NSString *)value result:(void(^)(OSStatus resultStatus))result;


/**
 keyChain删除值

 @param key 键
 @param result 结果回调 -- 是否成功(OSStatus等于errSecSuccess为成功)
 */
-(void) dv_keyChainDeleteWithKey:(NSString *)key result:(void(^)(OSStatus resultStatus))result;
@end

NS_ASSUME_NONNULL_END
