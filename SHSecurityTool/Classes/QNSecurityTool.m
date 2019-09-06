//
//  QNSecurityTool.m
//  QNSecurityTool
//
//  Created by rsh on 2019/8/2.
//  Copyright © 201年 qncx. All rights reserved.
//

#import "QNSecurityTool.h"
#import <CommonCrypto/CommonCrypto.h>
#import "ZZCXUUIDTool.h"

#define SIGN_SEED   @"147e62aaf0ec95c669a0f270ab78b964"

#define LOCAL_KEY   @"wsx258"
#define LOCAL_IV    @"147qaz"

typedef NS_ENUM(NSUInteger, QNAESOperationType) {
    QNAESOperationTypeEncrypt = 0,
    QNAESOperationTypeDecrypt
};

#pragma mark *******加密实现*******
@implementation QNSecurityTool

+ (nonnull NSString *)getDeviceUUID
{
//    NSString *uuid = [Theme zzcx_getUUID];
    NSString *uuid = [ZZCXUUIDTool getPhoneIdentifier];
    return uuid.length ? uuid : @"";
}

+ (nonnull NSString *)AESEncrypt:(NSString *)content
{
    return [self AESOperation:QNAESOperationTypeEncrypt
                          key:[self getAESPrivateKey]
                           iv:[self getAESPrivateIv]
                      content:content];
}

+ (nonnull NSString *)AESDecrypt:(NSString *)content
{
    return [self AESOperation:QNAESOperationTypeDecrypt
                          key:[self getAESPrivateKey]
                           iv:[self getAESPrivateIv]
                      content:content];
}

+ (nonnull NSString *)AESDecrypt:(NSString *)content randomKey:(NSString *)randomKey
{
    return [self AESOperation:QNAESOperationTypeDecrypt
                          key:[self getAESPrivateKeyWithRandomKey:randomKey]
                           iv:[self getAESPrivateIv]
                      content:content];
}

+ (nonnull NSString *)AESLocalEncrypt:(NSString *)content
{
    return [self AESOperation:QNAESOperationTypeEncrypt
                          key:[self getLocalAESPrivateKey]
                           iv:[self getLocalAESPrivateIv]
                      content:content];
}

+ (nonnull NSString *)AESLocalDecrypt:(NSString *)content
{
    return [self AESOperation:QNAESOperationTypeDecrypt
                          key:[self getLocalAESPrivateKey]
                           iv:[self getLocalAESPrivateIv]
                      content:content];
}

+ (nonnull NSString *)signWithCode:(NSString *)code data:(NSString *)data time:(NSString *)time
{
    NSMutableString *result = [[NSMutableString alloc] initWithCapacity:0];
    [result appendString:code];
    [result appendString:data];
    [result appendString:time];
    [result appendString:[[SIGN_SEED MD5Encode] uppercaseString]];
    [result appendString:SIGN_SEED];
    return [[result MD5Encode] uppercaseString];
}

+ (nonnull NSString *)signWithCode:(NSString *)code sender:(NSString *)sender data:(NSString *)data time:(NSString *)time
{
    NSMutableString *result = [[NSMutableString alloc] initWithCapacity:0];
    [result appendString:code];
    [result appendString:sender];
    [result appendString:data];
    [result appendString:time];
    [result appendString:[[SIGN_SEED MD5Encode] uppercaseString]];
    [result appendString:SIGN_SEED];
    return [[result MD5Encode] uppercaseString];
}

#pragma mark - Private
+ (nonnull NSString *)getAESPrivateKey
{
    NSString *str1 = [[[self getDeviceUUID] MD5Encode] uppercaseString];
    NSString *str2 = [[str1 MD5Encode] uppercaseString];
    return [str2 substringToIndex:16];
}

+ (nonnull NSString *)getAESPrivateIv
{
    NSString *str = [[SIGN_SEED MD5Encode] uppercaseString];
    return [str substringFromIndex:16];
}

+ (nonnull NSString *)getAESPrivateKeyWithRandomKey:(NSString *)randomKey
{
    if (!randomKey.length) return @"";
    NSString *str = [[randomKey MD5Encode] uppercaseString];
    return [str substringToIndex:16];
}

+ (nonnull NSString *)getLocalAESPrivateKey
{
    NSString *str = [[LOCAL_KEY MD5Encode] uppercaseString];
    return [str substringToIndex:16];
}

+ (nonnull NSString *)getLocalAESPrivateIv
{
    NSString *str = [[LOCAL_IV MD5Encode] uppercaseString];
    return [str substringFromIndex:16];
}

+ (nonnull NSString *)AESOperation:(QNAESOperationType)type key:(NSString *)key iv:(NSString *)iv content:(NSString *)content
{
    if (!content.length) return @"";
    if (!key.length) return @"";
    
    NSData *data = nil;
    if (type == QNAESOperationTypeEncrypt) {
        data = [content dataUsingEncoding:NSUTF8StringEncoding];
    }
    else {
        data = [[NSData alloc] initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
    }
        
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCKeySizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(type,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    
    if (cryptStatus != kCCSuccess) {
        free(buffer); return @"";
    }
    
    NSData *d = [NSData dataWithBytes:buffer length:numBytesEncrypted];
    NSString *result = @"";
    if (type == QNAESOperationTypeEncrypt) {
        result = [d base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }
    else {
        result = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    }
    
    // 去除base64中的\r与\n
    result = [result stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    result = [result stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    
    free(buffer);
    return result.length ? result : @"";
}

@end


#pragma mark *******编码实现*******
@implementation NSString (Encode)

/** MD5编码 */
- (nonnull NSString *)MD5Encode
{
    if (!self.length) return @"";
    const char *value = [self UTF8String];
    
    unsigned char outputBuffer[CC_MD5_DIGEST_LENGTH];
    CC_MD5(value, (int)strlen(value), outputBuffer);
    
    NSMutableString *result = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(NSInteger count = 0; count < CC_MD5_DIGEST_LENGTH; count++) {
        [result appendFormat:@"%02x",outputBuffer[count]];
    }
    return [result copy];
}

/** Base64编码 */
- (nonnull NSString *)base64Encode
{
    if (!self.length) return @"";
    NSData *d = [self dataUsingEncoding:NSUTF8StringEncoding];
    NSString *result = [d base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    // 去除base64中的\r与\n
    result = [result stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    result = [result stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    return result.length ? result : @"";
}

/** Base64解码 */
- (nonnull NSString *)base64Decode
{
    if (!self.length) return @"";
    NSData *d = [[NSData alloc] initWithBase64EncodedString:self options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSString *result = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    // 去除base64中的\r与\n
    result = [result stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    result = [result stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    return result.length ? result : @"";
}

@end

@implementation NSData (Encode)

/** Base64编码 */
- (nonnull NSData *)base64Encode
{
    if (!self.length) return [NSData data];
    return [self base64EncodedDataWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

/** Base64解码 */
- (nonnull NSData *)base64DecodeWithString:(nonnull NSString *)str
{
    if (!str.length) return [NSData data];
    return [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

@end
