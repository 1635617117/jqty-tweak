#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ========== 纯 ObjC Runtime Swizzling（不依赖 Cydia Substrate） ==========

static IMP swizzleInstance(Class cls, SEL sel, IMP newImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NULL;
    return method_setImplementation(m, newImp);
}

static IMP swizzleClass(Class cls, SEL sel, IMP newImp) {
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NULL;
    return method_setImplementation(m, newImp);
}

// ========== 日志 ==========
#define LOG_PATH @"/var/mobile/Library/Logs/AppPacketLog.txt"

static void slog(NSString *msg) {
    @try {
        NSString *dir = [LOG_PATH stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:NULL];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:LOG_PATH];
        if (!fh) {
            [[NSFileManager defaultManager] createFileAtPath:LOG_PATH contents:nil attributes:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:LOG_PATH];
        }
        [fh seekToEndOfFile];
        [fh writeData:[[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } @catch (...) {}
}

// ========== DCAFSecurityPolicy 绕过 ==========

static BOOL (*orig_DCAF_eval)(id, SEL, SecTrustRef, NSString *);
static BOOL new_DCAF_eval(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

// ========== DCAFSecurityPolicy +policyWithPinningMode: 绕过 ==========

static id (*orig_DCAF_policy)(Class, SEL, NSInteger);
static id new_DCAF_policy(Class cls, SEL _cmd, NSInteger mode) {
    id p = orig_DCAF_policy(cls, _cmd, mode);
    @try {
        [p setValue:@YES forKey:@"allowInvalidCertificates"];
        [p setValue:@NO forKey:@"validatesDomainName"];
        [p setValue:@(0) forKey:@"SSLPinningMode"];
    } @catch (...) {}
    return p;
}

// ========== WPKAFSecurityPolicy 绕过 ==========

static BOOL (*orig_WPKAF_eval)(id, SEL, SecTrustRef, NSString *);
static BOOL new_WPKAF_eval(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

// ========== UMConfigure +isJailbreak 绕过 ==========

static BOOL (*orig_UM_jb)(Class, SEL);
static BOOL new_UM_jb(Class cls, SEL _cmd) { return NO; }

// ========== 入口 ==========

__attribute__((constructor))
static void init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"HH:mm:ss";
        slog([NSString stringWithFormat:@"[%@] JQTYPacketLog v5 loaded (TrollStore, no Substrate)",
              [fmt stringFromDate:[NSDate date]]]);

        Class dcaf = NSClassFromString(@"DCAFSecurityPolicy");
        if (dcaf) {
            orig_DCAF_eval = (void *)swizzleInstance(dcaf, @selector(evaluateServerTrust:forDomain:),
                                                      (IMP)new_DCAF_eval);
            orig_DCAF_policy = (void *)swizzleClass(dcaf, @selector(policyWithPinningMode:),
                                                     (IMP)new_DCAF_policy);
            slog(@"DCAFSecurityPolicy bypassed");
        }

        Class wpk = NSClassFromString(@"WPKAFSecurityPolicy");
        if (wpk) {
            orig_WPKAF_eval = (void *)swizzleInstance(wpk, @selector(evaluateServerTrust:forDomain:),
                                                       (IMP)new_WPKAF_eval);
            slog(@"WPKAFSecurityPolicy bypassed");
        }

        Class um = NSClassFromString(@"UMConfigure");
        if (um) {
            orig_UM_jb = (void *)swizzleClass(um, @selector(isJailbreak),
                                               (IMP)new_UM_jb);
            slog(@"UMConfigure jailbreak bypassed");
        }

        slog(@"All hooks installed");
    });
}
