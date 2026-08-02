#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ========== 纯 ObjC Runtime Swizzling ==========

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

// ========== 日志（同步写文件，够用） ==========
#define LOG_PATH @"/var/mobile/Library/Logs/AppPacketLog.txt"
#define MAX_SIZE  (50 * 1024 * 1024)

static dispatch_queue_t gQueue;
static NSLock *gLock;
static unsigned long long gWritten;
static BOOL gReady;

static void logReady(void) {
    if (gReady) return;
    @synchronized([NSObject class]) {
        if (gReady) return;
        gLock = [[NSLock alloc] init];
        gQueue = dispatch_queue_create("jqty.log", DISPATCH_QUEUE_SERIAL);
        [[NSFileManager defaultManager] createDirectoryAtPath:[LOG_PATH stringByDeletingLastPathComponent]
                                  withIntermediateDirectories:YES attributes:nil error:NULL];
        if (![[NSFileManager defaultManager] fileExistsAtPath:LOG_PATH])
            [[NSFileManager defaultManager] createFileAtPath:LOG_PATH contents:nil attributes:nil];
        gReady = YES;
    }
}

static void writeLog(NSString *tag, NSData *data) {
    if (!data || data.length == 0) return;
    logReady();
    NSData *copy = [data copy];
    dispatch_async(gQueue, ^{
        [gLock lock];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:LOG_PATH];
        if (!fh) { [gLock unlock]; return; }
        [fh seekToEndOfFile];
        if (gWritten > MAX_SIZE) { [fh truncateFileAtOffset:0]; gWritten = 0; }
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"HH:mm:ss.SSS";
        NSString *header = [NSString stringWithFormat:@"[%@] %@ (%luB)\n",
                            [fmt stringFromDate:[NSDate date]], tag, (unsigned long)copy.length];
        // Hex dump
        NSMutableString *hex = [NSMutableString string];
        const uint8_t *b = (const uint8_t *)copy.bytes;
        for (NSUInteger i = 0; i < copy.length; i += 16) {
            [hex appendFormat:@"%04lx  ", (unsigned long)i];
            for (NSUInteger j = 0; j < 16; j++) {
                if (i + j < copy.length) [hex appendFormat:@"%02x ", b[i + j]];
                else [hex appendString:@"   "];
                if (j == 7) [hex appendString:@" "];
            }
            [hex appendString:@"|"];
            for (NSUInteger j = 0; j < 16 && (i + j) < copy.length; j++)
                [hex appendFormat:@"%c", (b[i+j] >= 0x20 && b[i+j] <= 0x7e) ? b[i+j] : '.'];
            [hex appendString:@"\n"];
        }
        // 尝试可读文本
        NSString *txt = [[NSString alloc] initWithData:copy encoding:NSUTF8StringEncoding];
        if (txt) [hex appendFormat:@"--- TEXT ---\n%@\n", txt];
        NSString *entry = [NSString stringWithFormat:@"%@%@\n", header, hex];
        [fh writeData:[entry dataUsingEncoding:NSUTF8StringEncoding]];
        [fh synchronizeFile];
        gWritten += entry.length;
        [fh closeFile];
        [gLock unlock];
    });
}

static void slog(NSString *msg) {
    writeLog(@"LOG", [msg dataUsingEncoding:NSUTF8StringEncoding]);
}

// ========== NSURLSession 请求/响应捕获 ==========

static IMP orig_dataTask;

static id new_dataTask(id self, SEL _cmd, NSURLRequest *req, void (^cb)(NSData *, NSURLResponse *, NSError *)) {
    NSString *tag = [NSString stringWithFormat:@"REQ %@ %@", req.HTTPMethod ?: @"?", req.URL.absoluteString ?: @"?"];
    if (req.HTTPBody) writeLog(tag, req.HTTPBody);

    void (^newCb)(NSData *, NSURLResponse *, NSError *) = ^(NSData *d, NSURLResponse *r, NSError *e) {
        if (d && d.length > 0) {
            NSString *rtag = [NSString stringWithFormat:@"RESP %@ %@ [%ld]", req.HTTPMethod ?: @"?",
                              req.URL.absoluteString ?: @"?", (long)((NSHTTPURLResponse *)r).statusCode];
            writeLog(rtag, d);
        }
        if (cb) cb(d, r, e);
    };
    return ((id (*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))orig_dataTask)(self, _cmd, req, newCb);
}

// ========== SSL Pinning 绕过 ==========

static IMP orig_DCAF_eval;
static BOOL new_DCAF_eval(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

static IMP orig_DCAF_policy;
static id new_DCAF_policy(Class cls, SEL _cmd, NSInteger mode) {
    id p = ((id (*)(Class, SEL, NSInteger))orig_DCAF_policy)(cls, _cmd, mode);
    @try {
        [p setValue:@YES forKey:@"allowInvalidCertificates"];
        [p setValue:@NO forKey:@"validatesDomainName"];
        [p setValue:@(0) forKey:@"SSLPinningMode"];
    } @catch (...) {}
    return p;
}

static IMP orig_WPKAF_eval;
static BOOL new_WPKAF_eval(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

// ========== 越狱检测绕过 ==========
static IMP orig_UM_jb;
static BOOL new_UM_jb(Class cls, SEL _cmd) { return NO; }

// ========== 入口 ==========

__attribute__((constructor))
static void init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        slog(@"JQTYPacketLog v6: +NSURLSession");

        // NSURLSession 数据捕获
        Class nsurl = NSClassFromString(@"NSURLSession");
        if (nsurl) {
            orig_dataTask = swizzleInstance(nsurl, @selector(dataTaskWithRequest:completionHandler:),
                                            (IMP)new_dataTask);
            slog(@"NSURLSession hooked");
        }

        // SSL Pinning
        Class dcaf = NSClassFromString(@"DCAFSecurityPolicy");
        if (dcaf) {
            orig_DCAF_eval = swizzleInstance(dcaf, @selector(evaluateServerTrust:forDomain:), (IMP)new_DCAF_eval);
            orig_DCAF_policy = swizzleClass(dcaf, @selector(policyWithPinningMode:), (IMP)new_DCAF_policy);
            slog(@"DCAFSecurityPolicy bypassed");
        }

        Class wpk = NSClassFromString(@"WPKAFSecurityPolicy");
        if (wpk) {
            orig_WPKAF_eval = swizzleInstance(wpk, @selector(evaluateServerTrust:forDomain:), (IMP)new_WPKAF_eval);
            slog(@"WPKAFSecurityPolicy bypassed");
        }

        // 越狱检测
        Class um = NSClassFromString(@"UMConfigure");
        if (um) {
            orig_UM_jb = swizzleClass(um, @selector(isJailbreak), (IMP)new_UM_jb);
            slog(@"UMConfigure bypassed");
        }

        slog(@"v6 ready");
    });
}
