#import <substrate.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>

// ========== 日志配置 ==========
#define LOG_PATH      @"/var/mobile/Library/Logs/AppPacketLog.txt"
#define MAX_FILE_SIZE (50 * 1024 * 1024) // 50MB

// ========== 工具函数 ==========

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
        totalWritten = [[[NSFileManager defaultManager] attributesOfItemAtPath:LOG_PATH error:NULL][NSFileSize] unsignedLongLongValue];
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

// Hex dump: 地址偏移 + hex + ascii 三列格式
static NSString *hexDump(NSData *data) {
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;
    if (len == 0) return @"(empty)";
    NSMutableString *out = [NSMutableString string];
    NSUInteger offset = 0;
    while (offset < len) {
        NSUInteger rowLen = MIN(16, len - offset);
        // Offset
        [out appendFormat:@"%08lx  ", (unsigned long)offset];
        // Hex
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
        // 也尝试打印可读文本
        NSString *utf8 = [[NSString alloc] initWithData:payload encoding:NSUTF8StringEncoding];
        NSString *readable = utf8 ? [NSString stringWithFormat:@"--- TEXT ---\n%@\n", utf8] : @"";
        NSString *block = [NSString stringWithFormat:@"%@%@%@", header, hex, readable];
        NSData *blockData = [block dataUsingEncoding:NSUTF8StringEncoding];
        @try {
            [logHandle writeData:blockData];
            [logHandle synchronizeFile];
            totalWritten += blockData.length;
        } @catch (NSException *e) {
            // 文件句柄失效时重新打开
            logHandle = [NSFileHandle fileHandleForWritingAtPath:LOG_PATH];
            [logHandle seekToEndOfFile];
        }
        [logLock unlock];
    });
}

// ========== Hook 1: Apple SSLRead — 捕获解密后的入站数据 ==========

typedef OSStatus (*SSLReadFunc)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static SSLReadFunc orig_SSLRead;

static OSStatus hooked_SSLRead(SSLContextRef context, void *data, size_t dataLength, size_t *processed) {
    OSStatus ret = orig_SSLRead(context, data, dataLength, processed);
    if (ret == noErr && *processed > 0) {
        NSData *payload = [NSData dataWithBytes:data length:*processed];
        writeToLog(@"RECV (SSLRead)", payload);
    }
    return ret;
}

// ========== Hook 2: Apple SSLWrite — 捕获解密后的出站数据 ==========

typedef OSStatus (*SSLWriteFunc)(SSLContextRef context, const void *data, size_t dataLength, size_t *processed);
static SSLWriteFunc orig_SSLWrite;

static OSStatus hooked_SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed) {
    if (dataLength > 0 && data != NULL) {
        NSData *payload = [NSData dataWithBytes:data length:dataLength];
        writeToLog(@"SEND (SSLWrite)", payload);
    }
    return orig_SSLWrite(context, data, dataLength, processed);
}

// ========== Hook 3: CCCrypt — 捕获应用层加解密明文 ==========

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
        NSString *algName = [NSString stringWithFormat:@"alg=%u", (unsigned)alg];
        if (dataIn && dataInLength > 0) {
            NSData *inData = [NSData dataWithBytes:dataIn length:dataInLength];
            writeToLog([NSString stringWithFormat:@"CCCrypt %@:IN (%@)", opName, algName], inData);
        }
        if (dataOut && dataOutMoved && *dataOutMoved > 0) {
            NSData *outData = [NSData dataWithBytes:dataOut length:*dataOutMoved];
            writeToLog([NSString stringWithFormat:@"CCCrypt %@:OUT (%@)", opName, algName], outData);
        }
    }
    return ret;
}

// ========== Hook 4: NSURLSession dataTask — HTTP 层补充捕获 ==========

@interface NSURLSession (PacketLog)
@end

static void (*orig_dataTaskWithRequest_completion)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));

static void hooked_dataTaskWithRequest_completion(id self, SEL _cmd,
    NSURLRequest *request, void (^origHandler)(NSData *, NSURLResponse *, NSError *)) {
    NSString *url = request.URL.absoluteString;
    NSString *method = request.HTTPMethod ?: @"GET";
    writeToLog([NSString stringWithFormat:@"REQ: %@ %@", method, url],
               request.HTTPBody ?: [NSData data]);
    void (^newHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) {
            writeToLog([NSString stringWithFormat:@"RESP: %@ %@", method, url], data);
        }
        if (origHandler) origHandler(data, response, error);
    };
    orig_dataTaskWithRequest_completion(self, _cmd, request, newHandler);
}

// ========== SSL Pinning 绕过 ==========

// --- DCAFSecurityPolicy ---
@interface DCAFSecurityPolicy : NSObject
@property (nonatomic, assign) NSInteger SSLPinningMode;
@property (nonatomic, assign) BOOL allowInvalidCertificates;
@property (nonatomic, assign) BOOL validatesDomainName;
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust forDomain:(NSString *)domain;
+ (instancetype)policyWithPinningMode:(NSInteger)mode;
@end

static BOOL (*orig_DCAF_evaluateServerTrust)(DCAFSecurityPolicy *, SEL, SecTrustRef, NSString *);
static BOOL hooked_DCAF_evaluateServerTrust(DCAFSecurityPolicy *self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    // 无条件信任
    self.allowInvalidCertificates = YES;
    self.validatesDomainName = NO;
    return YES;
}

static DCAFSecurityPolicy *(*orig_DCAF_policyWithPinningMode)(Class, SEL, NSInteger);
static DCAFSecurityPolicy *hooked_DCAF_policyWithPinningMode(Class cls, SEL _cmd, NSInteger mode) {
    DCAFSecurityPolicy *policy = orig_DCAF_policyWithPinningMode(cls, _cmd, mode);
    policy.allowInvalidCertificates = YES;
    policy.validatesDomainName = NO;
    // SSLPinningMode = 0 (AFSSLPinningModeNone)
    [policy setValue:@(0) forKey:@"SSLPinningMode"];
    return policy;
}

// --- WPKAFSecurityPolicy ---
@interface WPKAFSecurityPolicy : NSObject
@end

static BOOL (*orig_WPKAF_evaluateServerTrust)(WPKAFSecurityPolicy *, SEL, SecTrustRef, NSString *);
static BOOL hooked_WPKAF_evaluateServerTrust(WPKAFSecurityPolicy *self, SEL _cmd, SecTrustRef trust, NSString *domain) {
    return YES;
}

// --- DCSRWebSocket Pinning ---
@interface DCSRWebSocket : NSObject
@end

static void (*orig_DCSR_setPinnedCerts)(DCSRWebSocket *, SEL, NSArray *);
static void hooked_DCSR_setPinnedCerts(DCSRWebSocket *self, SEL _cmd, NSArray *certs) {
    // 清空 pinned certificates
    orig_DCSR_setPinnedCerts(self, _cmd, @[]);
}

// --- DCSecurityPolicy configTLSCertificate ---
@interface DCSecurityPolicy : NSObject
@end

static void (*orig_DCSecurity_configTLS)(DCSecurityPolicy *, SEL, id, id, id);
static void hooked_DCSecurity_configTLS(DCSecurityPolicy *self, SEL _cmd, id cert, id instance, id callback) {
    // 不做任何 pinning 配置
    if (callback) {
        // 如果 callback 是 block，直接调用表示成功
        void (^cb)(BOOL, id) = (void (^)(BOOL, id))callback;
        cb(YES, nil);
    }
}

// ========== 越狱检测绕过 (UMeng) ==========

@interface UMConfigure : NSObject
+ (BOOL)isJailbreak;
@end

static BOOL (*orig_UMConfigure_isJailbreak)(Class, SEL);
static BOOL hooked_UMConfigure_isJailbreak(Class cls, SEL _cmd) {
    return NO;
}

// ========== DC_AESCrypt / DC_RSA 应用层解密钩子 — 轻量级日志 ==========

static void (*orig_DC_AESCrypt_decryptData)(id, SEL, id, id);
static id hooked_DC_AESCrypt_decryptData(id self, SEL _cmd, id data, id password) {
    id result = orig_DC_AESCrypt_decryptData(self, _cmd, data, password);
    if (result && [result isKindOfClass:[NSData class]]) {
        writeToLog(@"DC_AESCrypt:decrypted", (NSData *)result);
    }
    return result;
}

// ========== 入口: MSHookFunction / MSHookMessageEx ==========

__attribute__((constructor))
static void init(void) {
    ensureLogReady();
    NSString *banner = @"\n===== JQTYPacketLog dylib loaded =====\n";
    [logHandle writeData:[banner dataUsingEncoding:NSUTF8StringEncoding]];
    [logHandle synchronizeFile];

    // --- C 函数 Hook (SSLRead/SSLWrite/CCCrypt) ---
    void *handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);

    MSHookFunction((void *)SSLRead, (void *)hooked_SSLRead, (void **)&orig_SSLRead);
    MSHookFunction((void *)SSLWrite, (void *)hooked_SSLWrite, (void **)&orig_SSLWrite);

    // CCCrypt 在 CommonCrypto 中，用 dlsym 获取
    void *cccrypt_ptr = dlsym(RTLD_DEFAULT, "CCCrypt");
    if (cccrypt_ptr) {
        MSHookFunction(cccrypt_ptr, (void *)hooked_CCCrypt, (void **)&orig_CCCrypt);
    }

    dlclose(handle);

    // --- ObjC 方法 Hook ---

    // NSURLSession dataTaskWithRequest:completionHandler:
    Class nsurlsession = NSClassFromString(@"NSURLSession");
    MSHookMessageEx(nsurlsession,
        @selector(dataTaskWithRequest:completionHandler:),
        (IMP)hooked_dataTaskWithRequest_completion,
        (IMP *)&orig_dataTaskWithRequest_completion);

    // DCAFSecurityPolicy
    Class dcaf = NSClassFromString(@"DCAFSecurityPolicy");
    if (dcaf) {
        MSHookMessageEx(dcaf,
            @selector(evaluateServerTrust:forDomain:),
            (IMP)hooked_DCAF_evaluateServerTrust,
            (IMP *)&orig_DCAF_evaluateServerTrust);
        MSHookMessageEx(object_getClass(dcaf),
            @selector(policyWithPinningMode:),
            (IMP)hooked_DCAF_policyWithPinningMode,
            (IMP *)&orig_DCAF_policyWithPinningMode);
    }

    // WPKAFSecurityPolicy
    Class wpkaf = NSClassFromString(@"WPKAFSecurityPolicy");
    if (wpkaf) {
        MSHookMessageEx(wpkaf,
            @selector(evaluateServerTrust:forDomain:),
            (IMP)hooked_WPKAF_evaluateServerTrust,
            (IMP *)&orig_WPKAF_evaluateServerTrust);
    }

    // DCSRWebSocket pinning
    Class dcsr = NSClassFromString(@"DCSRWebSocket");
    if (dcsr) {
        MSHookMessageEx(dcsr,
            @selector(setSR_SSLPinnedCertificates:),
            (IMP)hooked_DCSR_setPinnedCerts,
            (IMP *)&orig_DCSR_setPinnedCerts);
    }

    // DCSecurityPolicy
    Class dcsp = NSClassFromString(@"DCSecurityPolicy");
    if (dcsp) {
        MSHookMessageEx(dcsp,
            @selector(configTLSCertificate:weexInstance:callback:),
            (IMP)hooked_DCSecurity_configTLS,
            (IMP *)&orig_DCSecurity_configTLS);
    }

    // UMConfigure isJailbreak
    Class um = NSClassFromString(@"UMConfigure");
    if (um) {
        MSHookMessageEx(object_getClass(um),
            @selector(isJailbreak),
            (IMP)hooked_UMConfigure_isJailbreak,
            (IMP *)&orig_UMConfigure_isJailbreak);
    }

    // DC_AESCrypt decrypt
    Class dcaes = NSClassFromString(@"DC_AESCrypt");
    if (dcaes) {
        MSHookMessageEx(dcaes,
            @selector(decryptData:password:),
            (IMP)hooked_DC_AESCrypt_decryptData,
            (IMP *)&orig_DC_AESCrypt_decryptData);
    }
}
