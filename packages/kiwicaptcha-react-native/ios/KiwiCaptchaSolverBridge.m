// The Obj-C <-> Swift bridge that registers KiwiCaptchaSolver.swift as
// a React Native bridge module under exactly the name the JS layer
// looks up (docs/NATIVE.md): NativeModules.KiwiCaptchaSolver /
// TurboModuleRegistry.get("KiwiCaptchaSolver").

#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE (KiwiCaptchaSolver, NSObject)

RCT_EXTERN_METHOD(solve:(NSString *)challengeJson
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(solveWithProgress:(NSString *)challengeJson
                  progressResolver:(RCTResponseSenderBlock)progressResolver
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
