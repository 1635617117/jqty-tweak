#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ========== Runtime Swizzling ==========
static IMP swizzleInstance(Class cls, SEL sel, IMP newImp) {
    Method m = class_getInstanceMethod(cls, sel);
    return m ? method_setImplementation(m, newImp) : NULL;
}
static IMP swizzleClass(Class cls, SEL sel, IMP newImp) {
    Method m = class_getClassMethod(cls, sel);
    return m ? method_setImplementation(m, newImp) : NULL;
}

// ========== 日志 ==========
#define MAX_SIZE (50 * 1024 * 1024)

static dispatch_queue_t gQ;
static NSLock *gL;
static unsigned long long gW;
static NSFileHandle *gFH;
static NSString *gPath;

static void initLog(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gL = [[NSLock alloc] init];
        gQ = dispatch_queue_create("jq", DISPATCH_QUEUE_SERIAL);
        // 尝试多个路径
        NSArray *candidates = @[
            @"/var/mobile/Documents/jqty_packet.txt",
            @"/tmp/jqty_packet.txt",
            [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
             stringByAppendingPathComponent:@"jqty_packet.txt"]
        ];
        for (NSString *p in candidates) {
            @try {
                NSString *dir = [p stringByDeletingLastPathComponent];
                [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                          withIntermediateDirectories:YES attributes:nil error:NULL];
                if (![[NSFileManager defaultManager] fileExistsAtPath:p])
                    [[NSFileManager defaultManager] createFileAtPath:p contents:nil attributes:nil];
                gFH = [NSFileHandle fileHandleForWritingAtPath:p];
                if (gFH) { [gFH seekToEndOfFile]; gPath = p; break; }
            } @catch (...) {}
        }
        if (gPath) {
            NSString *banner = [NSString stringWithFormat:@"\n===== JQTYPacketLog =====\npath: %@\n", gPath];
            [gFH writeData:[banner dataUsingEncoding:NSUTF8StringEncoding]];
            [gFH synchronizeFile];
        }
    });
}

static void wlog(NSString *tag, NSData *d) {
    if (!d || !d.length) return;
    initLog();
    if (!gPath) return;
    NSData *copy = [d copy];
    dispatch_async(gQ, ^{
        [gL lock];
        @try {
            if (gW > MAX_SIZE) { [gFH truncateFileAtOffset:0]; gW = 0; }
            NSString *ts = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                         dateStyle:NSDateFormatterNoStyle
                                                         timeStyle:NSDateFormatterMediumStyle];
            NSString *header = [NSString stringWithFormat:@"[%@] %@ (%luB)\n", ts, tag, (unsigned long)copy.length];
            NSMutableString *hex = [NSMutableString string];
            const uint8_t *b = copy.bytes;
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
            NSString *txt = [[NSString alloc] initWithData:copy encoding:NSUTF8StringEncoding];
            if (txt) [hex appendFormat:@"--- TEXT ---\n%@\n", txt];
            NSString *entry = [NSString stringWithFormat:@"%@%@\n", header, hex];
            [gFH writeData:[entry dataUsingEncoding:NSUTF8StringEncoding]];
            [gFH synchronizeFile];
            gW += entry.length;
        } @catch (...) {}
        [gL unlock];
    });
}

// ========== NSURLSession 数据捕获 ==========
static IMP orig_dataTask;
static id new_dataTask(id self, SEL _cmd, NSURLRequest *req, void (^cb)(NSData *, NSURLResponse *, NSError *)) {
    NSString *tag = [NSString stringWithFormat:@"REQ %@ %@", req.HTTPMethod ?: @"?", req.URL.absoluteString ?: @"?"];
    if (req.HTTPBody) wlog(tag, req.HTTPBody);
    void (^nc)(NSData *, NSURLResponse *, NSError *) = ^(NSData *d, NSURLResponse *r, NSError *e) {
        if (d) wlog([NSString stringWithFormat:@"RESP %@ %@ [%ld]", req.HTTPMethod ?: @"?",
                     req.URL.absoluteString ?: @"?", (long)((NSHTTPURLResponse *)r).statusCode], d);
        if (cb) cb(d, r, e);
    };
    return ((id (*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))orig_dataTask)(self, _cmd, req, nc);
}

// ========== SSL Pinning 绕过 ==========
static IMP orig_DCAF_eval, orig_DCAF_policy, orig_WPKAF_eval, orig_UM_jb;
static BOOL new_DCAF_eval(id s, SEL c, SecTrustRef t, NSString *d) { return YES; }
static id new_DCAF_policy(Class cls, SEL _c, NSInteger m) {
    id p = ((id(*)(Class, SEL, NSInteger))orig_DCAF_policy)(cls, _c, m);
    @try { [p setValue:@YES forKey:@"allowInvalidCertificates"]; [p setValue:@NO forKey:@"validatesDomainName"]; [p setValue:@(0) forKey:@"SSLPinningMode"]; } @catch(...){}
    return p;
}
static BOOL new_WPKAF_eval(id s, SEL c, SecTrustRef t, NSString *d) { return YES; }
static BOOL new_UM_jb(Class c, SEL s) { return NO; }

// ========== Constructor: 立刻初始化日志，延迟装 Hook ==========
__attribute__((constructor))
static void init(void) {
    initLog(); // 立即创建日志文件
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        initLog();
        wlog(@"STATUS", [@"installing hooks..." dataUsingEncoding:NSUTF8StringEncoding]);
        
        Class ns = NSClassFromString(@"NSURLSession");
        if (ns) orig_dataTask = swizzleInstance(ns, @selector(dataTaskWithRequest:completionHandler:), (IMP)new_dataTask);
        
        Class dc = NSClassFromString(@"DCAFSecurityPolicy");
        if (dc) { orig_DCAF_eval = swizzleInstance(dc, @selector(evaluateServerTrust:forDomain:), (IMP)new_DCAF_eval); orig_DCAF_policy = swizzleClass(dc, @selector(policyWithPinningMode:), (IMP)new_DCAF_policy); }
        
        Class wk = NSClassFromString(@"WPKAFSecurityPolicy");
        if (wk) orig_WPKAF_eval = swizzleInstance(wk, @selector(evaluateServerTrust:forDomain:), (IMP)new_WPKAF_eval);
        
        Class um = NSClassFromString(@"UMConfigure");
        if (um) orig_UM_jb = swizzleClass(um, @selector(isJailbreak), (IMP)new_UM_jb);
        
        wlog(@"STATUS", [@"hooks installed" dataUsingEncoding:NSUTF8StringEncoding]);
    });
}
