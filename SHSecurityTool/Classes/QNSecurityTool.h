//
//  QNSecurityTool.h
//  QNSecurityTool
//
//  Created by rsh on 2019/8/2.
//  Copyright © 201年 qncx. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface QNSecurityTool : NSObject

/**
 *  获取设备的UUID
 *  @return UUID
 */
+ (nonnull NSString *)getDeviceUUID;

/**
 *  AES加密（针对请求体）
 *  @param content 明文
 *  @return 密文
 */
+ (nonnull NSString *)AESEncrypt:(NSString *)content;

/**
 *  AES解密（针对请求体）
 *  @param content 密文
 *  @return 明文
 */
+ (nonnull NSString *)AESDecrypt:(NSString *)content;

/**
 *  AES解密（针对响应体）
 *  @param content 密文
 *  @param randomKey 服务器返回的key
 *  @return 明文
 */
+ (nonnull NSString *)AESDecrypt:(NSString *)content randomKey:(NSString *)randomKey;

/**
 *  AES加密（针对本地存储）
 *  @param content 明文
 *  @return 密文
 */
+ (nonnull NSString *)AESLocalEncrypt:(NSString *)content;

/**
 *  AES解密（针对本地存储）
 *  @param content 密文
 *  @return 明文
 */
+ (nonnull NSString *)AESLocalDecrypt:(NSString *)content;

/**
 *  获取签名（普通请求）
 *  @param code 操作码
 *  @param data 数据json
 *  @param time 时间戳
 *  @return 签名
 */
+ (nonnull NSString *)signWithCode:(NSString *)code
                              data:(NSString *)data
                              time:(NSString *)time;

/**
 *  获取签名（消息请求）
 *  @param code 操作码
 *  @param sender 发送人
 *  @param data 数据json
 *  @param time 时间戳
 *  @return 签名
 */
+ (nonnull NSString *)signWithCode:(NSString *)code
                            sender:(NSString *)sender
                              data:(NSString *)data
                              time:(NSString *)time;

@end

@interface NSString (Encode)

/**
 *  MD5编码
 *  @return 编码结果
 */
- (nonnull NSString *)MD5Encode;

/**
 *  Base64编码
 *  @return 编码结果
 */
- (nonnull NSString *)base64Encode;

/**
 *  Base64解码
 *  @return 解码结果
 */
- (nonnull NSString *)base64Decode;

@end

@interface NSData (Encode)

/**
 *  Base64编码
 *  @return 编码结果
 */
- (nonnull NSData *)base64Encode;

/**
 *  Base64解码
 *  @str 要解密的字符串
 *  @return 解码结果
 */
- (nonnull NSData *)base64DecodeWithString:(nonnull NSString *)str;

@end
