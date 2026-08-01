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

// ========== 日志配置 ==========
#define LOG_PATH      @"/var/mobile/Library/Logs/AppPacketLog.txt"
#define MAX_FILE_SIZE (50 * 1024 * 1024)

// ========== 全局日志状态 ==========
static dispatch_queue_t logQueue;
static NSFileHandle *logHandle;
static NSLock *logLock;
static unsigned long long totalWritten;

static void ensureLogReady(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        logLock = [[NSLock alloc] init];
        logQueue = dispatch_queue_create("com.jqty.packetlog", DISPATCH_QUEUE_SERIAL);
        NSString *dir = [LOG_PATH stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:NULL];
        if (![[NSFileManager defaultManager] fileExistsAtPath:LOG_PATH]) {
            [[NSFileManager defaultManager] createFileAtPath:LOG_PATH contents:nil attributes:nil];
        }
        NSDictionary *attr = [[NSFileManager defaultManager] attributesOfItemAtPath:LOG_PATH error:NULL];
        totalWritten = [attr[NSFileSize] unsignedLongLongValue];
        logHandle = [NSFileHandle fileHandleForWritingAtPath:LOG_PATH];
        [logHandle seekToEndOfFile];
    });
}

static void checkAndClearIfNeeded(void) {
    if (totalWritten > MAX_FILE_SIZE) {
        [logHandle truncateFileAtOffset:0];
        totalWritten = 0;
    }
}

static NSString *hexDump(NSData *data) {
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;
    if (len == 0) return @"(empty)";
    NSMutableString *out = [NSMutableString string];
    NSUInteger offset = 0;
    while (offset < len) {
        NSUInteger rowLen = MIN(16, len - offset);
        [out appendFormat:@"%08lx  ", (unsigned long)offset];
        NSMutableString *hexPart = [NSMutableString string];
        NSMutableString *asciiPart = [NSMutableString string];
        for (NSUInteger i = 0; i < 16; i++) {
            if (i < rowLen) {
                uint8_t b = bytes[offset + i];
                [hexPart appendFormat:@"%02x ", b];
                [asciiPart appendFormat:@"%c", (b >= 0x20 && b <= 0x7e) ? b : '.'];
            } else {
                [hexPart appendString:@"   "];
            }
            if (i == 7) [hexPart appendString:@" "];
        }
        [out appendFormat:@"%@ %@\n", hexPart, asciiPart];
        offset += rowLen;
    }
    return out;
}

static void writeToLog(NSString *direction, NSData *payload) {
    ensureLogReady();
    dispatch_async(logQueue, ^{
        [logLock lock];
        checkAndClearIfNeeded();
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
        NSString *ts = [fmt stringFromDate:[NSDate date]];
        NSString *header = [NSString stringWithFormat:
            @"\n========== %@ (%@) [%lu bytes] ==========\n",
            direction, ts, (unsigned long)payload.length];
        NSString *hex = hexDump(payload);
        NSString *utf8 = [[NSString alloc] initWithData:payload encoding:NSUTF8StringEncoding];
        NSString *readable = utf8 ? [NSString stringWithFormat:@"--- TEXT ---\n%@\n", utf8] : @"";
        NSString *block = [NSString stringWithFormat:@"%@%@%@", header, hex, readable];
        NSData *blockData = [block dataUsingEncoding:NSUTF8StringEncoding];
        @try {
            [logHandle writeData:blockData];
            [logHandle synchronizeFile];
            totalWritten += blockData.length;
        } @catch (NSException *e) {
            logHandle = [NSFileHandle fileHandleForWritingAtPath:LOG_PATH];
            [logHandle seekToEndOfFile];
        }
        [logLock unlock];
    });
}

// ========== 1. SSLRead/SSLWrite Hook (动态获取避免 SDK26 签名冲突) ==========

typedef OSStatus (*SSLReadFunc_t)(SSLContextRef, void *, size_t, size_t *);
typedef OSStatus (*SSLWriteFunc_t)(SSLContextRef, const void *, size_t, size_t *);
static SSLReadFunc_t orig_SSLRead;
static SSLWriteFunc_t orig_SSLWrite;

static OSStatus hooked_SSLRead(SSLContextRef context, void *data, size_t dataLength, size_t *processed) {
    OSStatus ret = orig_SSLRead(context, data, dataLength, processed);
    if (ret == noErr && *processed > 0) {
        NSData *payload = [NSData dataWithBytes:data length:*processed];
        writeToLog(@"RECV (SSLRead)", payload);
    }
    return ret;
}

static OSStatus hooked_SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed) {
    if (dataLength > 0 && data != NULL) {
        NSData *payload = [NSData dataWithBytes:data length:dataLength];
        writeToLog(@"SEND (SSLWrite)", payload);
    }
    return orig_SSLWrite(context, data, dataLength, processed);
}

// ========== 3. CCCrypt Hook ==========

typedef CCCryptorStatus (*CCCryptFunc)(CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv, const void *dataIn,
    size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);
static CCCryptFunc orig_CCCrypt;

static CCCryptorStatus hooked_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv, const void *dataIn,
    size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    CCCryptorStatus ret = orig_CCCrypt(op, alg, options, key, keyLength,
                                       iv, dataIn, dataInLength,
                                       dataOut, dataOutAvailable, dataOutMoved);
    if (ret == kCCSuccess) {
        NSString *opName = (op == kCCEncrypt) ? @"ENCRYPT" : @"DECRYPT";
        NSString *tag = [NSString stringWithFormat:@"CCCrypt:%@", opName];
        if (dataIn && dataInLength > 0) {
            writeToLog([tag stringByAppendingString:@":IN"],
                       [NSData dataWithBytes:dataIn length:dataInLength]);
        }
        if (dataOut && dataOutMoved && *dataOutMoved > 0) {
            writeToLog([tag stringByAppendingString:@":OUT"],
                       [NSData dataWithBytes:dataOut length:*dataOutMoved]);
        }
    }
    return ret;
}

// ========== 4. NSURLSession dataTask Hook ==========

typedef NSURLSessionDataTask *(*dataTaskWithCompletionType)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static dataTaskWithCompletionType orig_dataTaskWithCompletion;

static NSURLSessionDataTask *hooked_dataTaskWithCompletion(id self, SEL _cmd,
    NSURLRequest *request, void (^origHandler)(NSData *, NSURLResponse *, NSError *)) {

    NSString *url = request.URL.absoluteString ?: @"";
    NSString *method = request.HTTPMethod ?: @"GET";
    writeToLog([NSString stringWithFormat:@"REQ: %@ %@", method, url],
               request.HTTPBody ?: [NSData data]);

    void (^newHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) {
            writeToLog([NSString stringWithFormat:@"RESP: %@ %@", method, url], data);
        }
        if (origHandler) origHandler(data, response, error);
    };
    return orig_dataTaskWithCompletion(self, _cmd, request, newHandler);
}

// ========== 5. SSL Pinning 绕过 ==========

// --- DCAFSecurityPolicy ---
static BOOL (*orig_DCAF_evaluate)(id, SEL, SecTrustRef, NSString *);
static BOOL hooked_DCAF_evaluate(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    // 强制设置属性绕过 pinning
    [self setValue:@YES forKey:@"allowInvalidCertificates"];
    [self setValue:@NO forKey:@"validatesDomainName"];
    return YES;
}

static id (*orig_DCAF_policyWithMode)(Class, SEL, NSInteger);
static id hooked_DCAF_policyWithMode(Class cls, SEL _cmd, NSInteger mode) {
    id policy = orig_DCAF_policyWithMode(cls, _cmd, mode);
    [policy setValue:@YES forKey:@"allowInvalidCertificates"];
    [policy setValue:@NO forKey:@"validatesDomainName"];
    [policy setValue:@(0) forKey:@"SSLPinningMode"];
    return policy;
}

// --- WPKAFSecurityPolicy ---
static BOOL (*orig_WPKAF_evaluate)(id, SEL, SecTrustRef, NSString *);
static BOOL hooked_WPKAF_evaluate(id self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

// --- DCSRWebSocket: 清空 pinned certs ---
static void (*orig_DCSR_setCerts)(id, SEL, NSArray *);
static void hooked_DCSR_setCerts(id self, SEL _cmd, NSArray *certs) {
    orig_DCSR_setCerts(self, _cmd, @[]);
}

// --- DCSecurityPolicy ---
static void (*orig_DCS_configTLS)(id, SEL, id, id, id);
static void hooked_DCS_configTLS(id self, SEL _cmd, id cert, id instance, id callback) {
    if (callback) {
        void (^cb)(BOOL, id) = (void (^)(BOOL, id))callback;
        cb(YES, nil);
    }
}

// ========== 6. UMeng 越狱检测绕过 ==========
static BOOL (*orig_UM_isJailbreak)(Class, SEL);
static BOOL hooked_UM_isJailbreak(Class cls, SEL _cmd) {
    return NO;
}

// ========== 7. DC_AESCrypt 解密 Hook ==========
static id (*orig_DCAES_decrypt)(id, SEL, id, id);
static id hooked_DCAES_decrypt(id self, SEL _cmd, id data, id password) {
    id result = orig_DCAES_decrypt(self, _cmd, data, password);
    if (result && [result isKindOfClass:[NSData class]]) {
        writeToLog(@"DC_AESCrypt:decrypted", (NSData *)result);
    }
    return result;
}

// ========== 入口 ==========

__attribute__((constructor))
static void init(void) {
    ensureLogReady();
    NSString *banner = @"\n===== JQTYPacketLog dylib loaded =====\n";
    [logHandle writeData:[banner dataUsingEncoding:NSUTF8StringEncoding]];
    [logHandle synchronizeFile];

    NSLog(@"JQTYPacketLog: Initializing hooks...");

    // --- SSLRead/SSLWrite (dlsym, avoid SDK26 declaration conflict) ---
    void *sslReadPtr = dlsym(RTLD_DEFAULT, "SSLRead");
    void *sslWritePtr = dlsym(RTLD_DEFAULT, "SSLWrite");
    if (sslReadPtr) {
        MSHookFunction(sslReadPtr, (void *)hooked_SSLRead, (void **)&orig_SSLRead);
        NSLog(@"JQTYPacketLog: SSLRead hooked");
    }
    if (sslWritePtr) {
        MSHookFunction(sslWritePtr, (void *)hooked_SSLWrite, (void **)&orig_SSLWrite);
        NSLog(@"JQTYPacketLog: SSLWrite hooked");
    }

    void *cccrypt_ptr = dlsym(RTLD_DEFAULT, "CCCrypt");
    if (cccrypt_ptr) {
        MSHookFunction(cccrypt_ptr, (void *)hooked_CCCrypt, (void **)&orig_CCCrypt);
        NSLog(@"JQTYPacketLog: CCCrypt hooked");
    }

    // --- NSURLSession ---
    Class nsurlsession = NSClassFromString(@"NSURLSession");
    if (nsurlsession) {
        MSHookMessageEx(nsurlsession,
            @selector(dataTaskWithRequest:completionHandler:),
            (IMP)hooked_dataTaskWithCompletion,
            (IMP *)&orig_dataTaskWithCompletion);
        NSLog(@"JQTYPacketLog: NSURLSession dataTask hooked");
    }

    // --- DCAFSecurityPolicy ---
    Class dcaf = NSClassFromString(@"DCAFSecurityPolicy");
    if (dcaf) {
        MSHookMessageEx(dcaf, @selector(evaluateServerTrust:forDomain:),
            (IMP)hooked_DCAF_evaluate, (IMP *)&orig_DCAF_evaluate);
        MSHookMessageEx(object_getClass(dcaf), @selector(policyWithPinningMode:),
            (IMP)hooked_DCAF_policyWithMode, (IMP *)&orig_DCAF_policyWithMode);
        NSLog(@"JQTYPacketLog: DCAFSecurityPolicy bypassed");
    }

    // --- WPKAFSecurityPolicy ---
    Class wpkaf = NSClassFromString(@"WPKAFSecurityPolicy");
    if (wpkaf) {
        MSHookMessageEx(wpkaf, @selector(evaluateServerTrust:forDomain:),
            (IMP)hooked_WPKAF_evaluate, (IMP *)&orig_WPKAF_evaluate);
        NSLog(@"JQTYPacketLog: WPKAFSecurityPolicy bypassed");
    }

    // --- DCSRWebSocket ---
    Class dcsr = NSClassFromString(@"DCSRWebSocket");
    if (dcsr) {
        MSHookMessageEx(dcsr, @selector(setSR_SSLPinnedCertificates:),
            (IMP)hooked_DCSR_setCerts, (IMP *)&orig_DCSR_setCerts);
        NSLog(@"JQTYPacketLog: DCSRWebSocket pinning bypassed");
    }

    // --- DCSecurityPolicy ---
    Class dcsp = NSClassFromString(@"DCSecurityPolicy");
    if (dcsp) {
        MSHookMessageEx(dcsp, @selector(configTLSCertificate:weexInstance:callback:),
            (IMP)hooked_DCS_configTLS, (IMP *)&orig_DCS_configTLS);
        NSLog(@"JQTYPacketLog: DCSecurityPolicy bypassed");
    }

    // --- UMConfigure isJailbreak ---
    Class um = NSClassFromString(@"UMConfigure");
    if (um) {
        MSHookMessageEx(object_getClass(um), @selector(isJailbreak),
            (IMP)hooked_UM_isJailbreak, (IMP *)&orig_UM_isJailbreak);
        NSLog(@"JQTYPacketLog: UMConfigure isJailbreak bypassed");
    }

    // --- DC_AESCrypt ---
    Class dcaes = NSClassFromString(@"DC_AESCrypt");
    if (dcaes) {
        MSHookMessageEx(dcaes, @selector(decryptData:password:),
            (IMP)hooked_DCAES_decrypt, (IMP *)&orig_DCAES_decrypt);
        NSLog(@"JQTYPacketLog: DC_AESCrypt decrypt hooked");
    }

    NSLog(@"JQTYPacketLog: All hooks installed. Log: %@", LOG_PATH);
}
