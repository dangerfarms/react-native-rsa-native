#import <CommonCrypto/CommonHMAC.h>
#import "RSANativeLegacy.h"
#import "RSAFormatter.h"

@interface RSANativeLegacy ()
@property (nonatomic) NSString *keyTag;
@property (nonatomic) SecKeyRef privateKeyRef;
@end

@implementation RSANativeLegacy

- (instancetype)initWithKeyTag:(NSString *)keyTag {
    self = [super init];
    if (self) {
        _keyTag = keyTag;
    }
    return self;
}

- (void)setPrivateKey:(NSString *)privateKey {
    privateKey = [RSAFormatter stripHeaders: privateKey];

    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                              (id)kSecAttrKeySizeInBits: @2048,
                              };
    CFErrorRef error = NULL;
    NSData *data = [[NSData alloc] initWithBase64EncodedString:privateKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)data,
                                         (__bridge CFDictionaryRef)options,
                                         &error);
    if (!key) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    } else {
        _privateKeyRef = key;
    }
}

- (NSString *)sign:(NSString *)message {
    NSData* data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *encodedSignature = [self _sign: data];
    return encodedSignature;
}

- (NSString *)_sign:(NSData *)messageBytes {
    __block NSString *encodedSignature = nil;
    size_t signedHashBytesSize = SecKeyGetBlockSize(_privateKeyRef);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);

    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([messageBytes bytes], (CC_LONG)[messageBytes length], hashBytes)) {
        return nil;
    }

    SecKeyRawSign(_privateKeyRef,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);

    NSData* signature = [NSData dataWithBytes:signedHashBytes length:(NSUInteger)signedHashBytesSize];

    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);

    encodedSignature = [signature base64EncodedStringWithOptions:0];
    encodedSignature = [encodedSignature stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    encodedSignature = [encodedSignature stringByReplacingOccurrencesOfString:@"+" withString:@"-"];

    return encodedSignature;
}

@end
