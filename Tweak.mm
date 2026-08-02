#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// Substrate hook 函数声明
extern "C" {
void MSHookFunction(void *symbol, void *replace, void **result);
void MSHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result);
}

// ========== 日志 ==========
#define LOG_PATH      @"/var/mobile/Library/Logs/AppPacketLog.txt"
#define MAX_FILE_SIZE (50 * 1024 * 1024)

static dispatch_queue_t logQueue;
static NSFileHandle *logHandle;
static NSLock *logLock;
static unsigned long long totalWritten;
static BOOL logReady = NO;

static void ensureLogReady(void) {
    if (logReady) return;
    @synchronized([NSObject class]) {
        if (logReady) return;
        logLock = [[NSLock alloc] init];
        logQueue = dispatch_queue_create("com.jqty.packetlog", DISPATCH_QUEUE_SERIAL);
        NSString *dir = [LOG_PATH stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:NULL];
        if (![[NSFileManager defaultManager] fileExistsAtPath:LOG_PATH])
            [[NSFileManager defaultManager] createFileAtPath:LOG_PATH contents:nil attributes:nil];
        NSDictionary *attr = [[NSFileManager defaultManager] attributesOfItemAtPath:LOG_PATH error:NULL];
        totalWritten = [attr[NSFileSize] unsignedLongLongValue];
        logHandle = [NSFileHandle fileHandleForWritingAtPath:LOG_PATH];
        [logHandle seekToEndOfFile];
        logReady = YES;
    }
}

static void writeToLog(NSString *tag, NSData *payload) {
    if (!payload || payload.length == 0) return;
    ensureLogReady();
    dispatch_async(logQueue, ^{
        [logLock lock];
        if (totalWritten > MAX_FILE_SIZE && logHandle) {
            [logHandle truncateFileAtOffset:0];
            totalWritten = 0;
        }
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"HH:mm:ss.SSS";
        NSString *ts = [fmt stringFromDate:[NSDate date]];
        NSString *line = [NSString stringWithFormat:@"[%@] %@ (%luB)\n", ts, tag, (unsigned long)payload.length];
        // Hex dump: 每行 16 字节
        NSMutableString *hex = [NSMutableString string];
        const uint8_t *bytes = (const uint8_t *)payload.bytes;
        for (NSUInteger i = 0; i < payload.length; i += 16) {
            [hex appendFormat:@"%04lx  ", (unsigned long)i];
            for (NSUInteger j = 0; j < 16; j++) {
                if (i + j < payload.length)
                    [hex appendFormat:@"%02x ", bytes[i + j]];
                else
                    [hex appendString:@"   "];
                if (j == 7) [hex appendString:@" "];
            }
            [hex appendString:@"|"];
            for (NSUInteger j = 0; j < 16 && (i + j) < payload.length; j++)
                [hex appendFormat:@"%c", (bytes[i+j] >= 0x20 && bytes[i+j] <= 0x7e) ? bytes[i+j] : '.'];
            [hex appendString:@"\n"];
        }
        NSString *block = [NSString stringWithFormat:@"%@%@", line, hex];
        @try {
            [logHandle writeData:[block dataUsingEncoding:NSUTF8StringEncoding]];
            [logHandle synchronizeFile];
            totalWritten += block.length;
        } @catch (...) { logReady = NO; }
        [logLock unlock];
    });
}

// ========== 1. NSURLSession 请求/响应捕获 ==========
static id (*orig_dataTask)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));

static id hooked_dataTask(id self, SEL _cmd, NSURLRequest *req, void (^cb)(NSData *, NSURLResponse *, NSError *)) {
    NSString *tag = [NSString stringWithFormat:@"REQ %@ %@", req.HTTPMethod ?: @"?", req.URL.absoluteString ?: @"?"];
    if (req.HTTPBody) writeToLog(tag, req.HTTPBody);
    void (^newCb)(NSData *, NSURLResponse *, NSError *) = ^(NSData *d, NSURLResponse *r, NSError *e) {
        if (d) writeToLog([@"RESP " stringByAppendingString:tag], d);
        if (cb) cb(d, r, e);
    };
    return orig_dataTask(self, _cmd, req, newCb);
}

// ========== 2. CCCrypt 解密明文捕获 ==========
typedef CCCryptorStatus (*CCCrypt_t)(CCOperation, CCAlgorithm, CCOptions,
    const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *);
static CCCrypt_t orig_CCCrypt;

static CCCryptorStatus hooked_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt,
    const void *key, size_t kLen, const void *iv, const void *in, size_t inLen,
    void *out, size_t outAvail, size_t *outMoved) {
    CCCryptorStatus ret = orig_CCCrypt(op, alg, opt, key, kLen, iv, in, inLen, out, outAvail, outMoved);
    if (ret == kCCSuccess && op == kCCDecrypt && out && outMoved && *outMoved > 0) {
        writeToLog(@"CRYPT:DEC", [NSData dataWithBytesNoCopy:out length:*outMoved freeWhenDone:NO]);
    }
    return ret;
}

// ========== 3. SSL Pinning 绕过 ==========

// DCAFSecurityPolicy - evaluateServerTrust:
static BOOL (*orig_DCAF_eval)(id, SEL, SecTrustRef, NSString *);
static BOOL hooked_DCAF_eval(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

// DCAFSecurityPolicy +policyWithPinningMode:
static id (*orig_DCAF_policy)(Class, SEL, NSInteger);
static id hooked_DCAF_policy(Class cls, SEL _cmd, NSInteger mode) {
    id p = orig_DCAF_policy(cls, _cmd, mode);
    [p setValue:@YES forKey:@"allowInvalidCertificates"];
    [p setValue:@NO forKey:@"validatesDomainName"];
    [p setValue:@(0) forKey:@"SSLPinningMode"];
    return p;
}

// WPKAFSecurityPolicy
static BOOL (*orig_WPKAF_eval)(id, SEL, SecTrustRef, NSString *);
static BOOL hooked_WPKAF_eval(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

// ========== 4. 越狱检测绕过 ==========
static BOOL (*orig_UM_jb)(Class, SEL);
static BOOL hooked_UM_jb(Class cls, SEL _cmd) { return NO; }

// ========== 安全 Hook 包装 ==========
static void safeHookClass(NSString *className, NSString *selName, IMP newImp, IMP *origImp) {
    Class cls = NSClassFromString(className);
    if (!cls) return;
    SEL sel = NSSelectorFromString(selName);
    if (!sel) return;
    MSHookMessageEx(cls, sel, newImp, origImp);
}

static void safeHookClassMethod(NSString *className, NSString *selName, IMP newImp, IMP *origImp) {
    Class cls = NSClassFromString(className);
    if (!cls) return;
    SEL sel = NSSelectorFromString(selName);
    if (!sel) return;
    MSHookMessageEx(object_getClass(cls), sel, newImp, origImp);
}

static void safeHookCFunction(const char *name, void *rep, void **orig) {
    void *ptr = dlsym(RTLD_DEFAULT, name);
    if (ptr) MSHookFunction(ptr, rep, orig);
}

// ========== 延迟初始化 — 等 App 跑起来再装 Hook ==========
static void installHooks(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 写个 banner 确认 dylib 被加载了
        ensureLogReady();
        writeToLog(@"HOOKS:INSTALL", [@"JQTYPacketLog v2 loaded" dataUsingEncoding:NSUTF8StringEncoding]);

        // 1) NSURLSession — 安全稳定，不会崩
        safeHookClass(@"NSURLSession", @"dataTaskWithRequest:completionHandler:",
                      (IMP)hooked_dataTask, (IMP *)&orig_dataTask);

        // 2) CCCrypt — 通过 dlsym 避免 SDK 签名冲突
        safeHookCFunction("CCCrypt", (void *)hooked_CCCrypt, (void **)&orig_CCCrypt);

        // 3) SSL Pinning 绕过
        safeHookClass(@"DCAFSecurityPolicy", @"evaluateServerTrust:forDomain:",
                      (IMP)hooked_DCAF_eval, (IMP *)&orig_DCAF_eval);
        safeHookClassMethod(@"DCAFSecurityPolicy", @"policyWithPinningMode:",
                            (IMP)hooked_DCAF_policy, (IMP *)&orig_DCAF_policy);
        safeHookClass(@"WPKAFSecurityPolicy", @"evaluateServerTrust:forDomain:",
                      (IMP)hooked_WPKAF_eval, (IMP *)&orig_WPKAF_eval);

        // 4) 越狱检测
        safeHookClassMethod(@"UMConfigure", @"isJailbreak",
                            (IMP)hooked_UM_jb, (IMP *)&orig_UM_jb);

        writeToLog(@"HOOKS:DONE", [@"All hooks installed" dataUsingEncoding:NSUTF8StringEncoding]);
    });
}

// ========== Constructor: 延迟到下一个 RunLoop 初始化 ==========
__attribute__((constructor))
static void init(void) {
    // 什么都不要在 constructor 里直接做!
    // 等主线程空闲了再装 hook，避免干扰 App 启动流程
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            installHooks();
        } @catch (NSException *e) {
            // 吞掉异常，不闪退
        }
    });
}
