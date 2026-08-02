#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>

extern "C" {
void MSHookFunction(void *symbol, void *replace, void **result);
void MSHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result);
}

// ========== 轻量级日志（直接同步写，不搞队列） ==========
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
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"HH:mm:ss";
        NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
                          [fmt stringFromDate:[NSDate date]], msg];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } @catch (...) {}
}

// ========== SSL Pinning 绕过 ==========

static BOOL (*orig_DCAF_eval)(id, SEL, SecTrustRef, NSString *);
static BOOL hooked_DCAF_eval(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

static id (*orig_DCAF_policy)(Class, SEL, NSInteger);
static id hooked_DCAF_policy(Class cls, SEL _cmd, NSInteger mode) {
    id p = orig_DCAF_policy(cls, _cmd, mode);
    @try {
        [p setValue:@YES forKey:@"allowInvalidCertificates"];
        [p setValue:@NO forKey:@"validatesDomainName"];
        [p setValue:@(0) forKey:@"SSLPinningMode"];
    } @catch (...) {}
    return p;
}

static BOOL (*orig_WPKAF_eval)(id, SEL, SecTrustRef, NSString *);
static BOOL hooked_WPKAF_eval(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

// ========== 越狱检测绕过 ==========
static BOOL (*orig_UM_jb)(Class, SEL);
static BOOL hooked_UM_jb(Class cls, SEL _cmd) { return NO; }

// ========== 安全 Hook ==========
static void tryHook(NSString *clsName, NSString *selName, IMP imp, IMP *orig, BOOL classMethod) {
    Class cls = NSClassFromString(clsName);
    if (!cls) return;
    if (classMethod) cls = object_getClass(cls);
    SEL sel = NSSelectorFromString(selName);
    if (!sel) return;
    MSHookMessageEx(cls, sel, imp, orig);
}

// ========== 入口 ==========
__attribute__((constructor))
static void init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        slog(@"JQTYPacketLog v4: SSL bypass only");
        
        tryHook(@"DCAFSecurityPolicy", @"evaluateServerTrust:forDomain:",
                (IMP)hooked_DCAF_eval, (IMP *)&orig_DCAF_eval, NO);
        tryHook(@"DCAFSecurityPolicy", @"policyWithPinningMode:",
                (IMP)hooked_DCAF_policy, (IMP *)&orig_DCAF_policy, YES);
        tryHook(@"WPKAFSecurityPolicy", @"evaluateServerTrust:forDomain:",
                (IMP)hooked_WPKAF_eval, (IMP *)&orig_WPKAF_eval, NO);
        tryHook(@"UMConfigure", @"isJailbreak",
                (IMP)hooked_UM_jb, (IMP *)&orig_UM_jb, YES);
        
        slog(@"v4 hooks installed");
    });
}
