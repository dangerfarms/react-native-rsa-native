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
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:privateKey options:NSDataBase64DecodingIgnoreUnknownCharacters];

    //a tag to read/write keychain storage
    NSString *tag = @"RNRSA_TEMP_KEY";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];

    NSMutableDictionary *keyAddDict = [[NSMutableDictionary alloc] init];
    [keyAddDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAddDict setObject:(id)kSecAttrAccessibleWhenUnlocked forKey:(id)kSecAttrAccessible];
    [keyAddDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAddDict setObject:d_tag forKey:(id)kSecAttrApplicationTag];
    SecItemDelete((CFDictionaryRef)keyAddDict);

    [keyAddDict setObject:data forKey:(__bridge id)kSecValueData];
    [keyAddDict setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [keyAddDict setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];

    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((CFDictionaryRef)keyAddDict, &persistKey);

    if (persistKey != nil) {
        CFRelease(persistKey);
    }

    NSMutableDictionary *keyCopyDict = [[NSMutableDictionary alloc] init];
    [keyCopyDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyCopyDict setObject:(id)kSecAttrAccessibleWhenUnlocked forKey:(id)kSecAttrAccessible];
    [keyCopyDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyCopyDict setObject:d_tag forKey:(id)kSecAttrApplicationTag];
    [keyCopyDict setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [keyCopyDict setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];

    CFTypeRef key = nil;
    OSStatus copyStatus = SecItemCopyMatching((CFDictionaryRef)keyCopyDict, (CFTypeRef *)&key);

    _privateKeyRef = (SecKeyRef) key;
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
