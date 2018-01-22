#import "RNSign.h"
#import "RSANativeLegacy.h"

@implementation RNSign

- (dispatch_queue_t)methodQueue {
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(sign:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANativeLegacy *rsa = [[RSANativeLegacy alloc] init];
    rsa.privateKey = key;
    NSString *signature = [rsa sign:message];
    resolve(signature);
}

@end
