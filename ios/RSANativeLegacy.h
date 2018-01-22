@import Foundation;

@interface RSANativeLegacy : NSObject

@property (nonatomic) NSString *publicKey;
@property (nonatomic) NSString *privateKey;

- (instancetype)initWithKeyTag:(NSString *)keyTag;
- (NSString *)sign:(NSString *)message;
- (NSString *)_sign:(NSData *)messageBytes;

@end

