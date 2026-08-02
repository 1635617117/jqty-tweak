#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ========== 数据存储 ==========
#define MAX_ENTRIES 300
static NSMutableArray *entries;
static BOOL gOn = NO;
static void (^gRefresh)(void);

static void store(NSString *type, NSString *url, NSData *data) {
    if (!gOn || !data || data.length == 0) return;
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSString *ts = [NSDateFormatter localizedStringFromDate:[NSDate date] dateStyle:NSDateFormatterNoStyle timeStyle:NSDateFormatterMediumStyle];
        NSMutableString *hex = [NSMutableString string];
        const uint8_t *b = (const uint8_t *)data.bytes;
        NSUInteger N = MIN(data.length, 200);
        for (NSUInteger i = 0; i < N; i += 16) {
            [hex appendFormat:@"%04lx  ", (unsigned long)i];
            for (NSUInteger j = 0; j < 16 && (i+j) < N; j++) [hex appendFormat:@"%02x ", b[i+j]];
            [hex appendString:@"\n"];
        }
        NSString *txt = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSString *body = txt ? txt : hex;
        NSString *e = [NSString stringWithFormat:@"[%@] %@ %@\n%@\n---\n", ts, type, url, body];
        @synchronized(entries) { [entries addObject:e]; while (entries.count > MAX_ENTRIES) [entries removeObjectAtIndex:0]; }
        dispatch_async(dispatch_get_main_queue(), ^{ if (gRefresh) gRefresh(); });
    });
}

// ========== NSURLProtocol 全局拦截 ==========
@interface JQTYProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic) NSURLSessionDataTask *task;
@property (nonatomic) NSMutableData *respData;
@end

@implementation JQTYProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    // 不拦截自己发出的请求（通过标记 header 判断）
    if ([NSURLProtocol propertyForKey:@"JQTYHandled" inRequest:request]) return NO;
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"JQTYHandled" inRequest:req];
    
    // 记录请求
    NSString *url = req.URL.absoluteString ?: @"";
    NSString *method = req.HTTPMethod ?: @"GET";
    if (req.HTTPBody) store(@"REQ", [NSString stringWithFormat:@"%@ %@", method, url], req.HTTPBody);
    
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    cfg.protocolClasses = @[];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:req];
    self.respData = [NSMutableData data];
    [self.task resume];
}

- (void)stopLoading {
    [self.task cancel];
    self.task = nil;
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.respData appendData:data];
    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
 didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
    } else {
        // 记录响应
        NSString *url = self.request.URL.absoluteString ?: @"";
        NSString *method = self.request.HTTPMethod ?: @"GET";
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)task.response;
        store(@"RESP", [NSString stringWithFormat:@"%@ %@ [%ld]", method, url, (long)httpResp.statusCode], self.respData);
        [self.client URLProtocolDidFinishLoading:self];
    }
    [session finishTasksAndInvalidate];
}

@end

// ========== 悬浮窗 ==========
@interface JQTYWin : UIWindow
- (void)refresh;
@end

@implementation JQTYWin {
    UIButton *_tBtn, *_lBtn, *_cBtn;
    UITextView *_tv;
    UILabel *_st;
    BOOL _exp;
}

- (instancetype)init {
    CGRect s = [UIScreen mainScreen].bounds;
    self = [super initWithFrame:CGRectMake(30, s.size.height - 164, s.size.width - 60, 44)];
    if (self) {
        self.windowLevel = UIWindowLevelAlert + 100;
        self.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.88];
        self.layer.cornerRadius = 22; self.layer.masksToBounds = YES;
        self.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:0.6].CGColor;
        self.layer.borderWidth = 1;
        self.hidden = NO;

        UIPanGestureRecognizer *p = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)];
        [self addGestureRecognizer:p];

        CGFloat bw = (self.bounds.size.width - 20) / 3;
        _tBtn = [self btn:@"● OFF" act:@selector(tTap) f:CGRectMake(5, 2, bw, 40)];
        _lBtn = [self btn:@"LOG" act:@selector(lTap) f:CGRectMake(10+bw, 2, bw, 40)];
        _cBtn = [self btn:@"CLR" act:@selector(cTap) f:CGRectMake(15+bw*2, 2, bw, 40)];
        [self addSubview:_tBtn]; [self addSubview:_lBtn]; [self addSubview:_cBtn];

        _tv = [[UITextView alloc] init];
        _tv.backgroundColor = [UIColor colorWithWhite:0.03 alpha:0.95];
        _tv.textColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
        _tv.font = [UIFont fontWithName:@"Courier" size:10] ?: [UIFont systemFontOfSize:10];
        _tv.editable = NO; _tv.hidden = YES;
        [self addSubview:_tv];
        
        _st = [[UILabel alloc] initWithFrame:CGRectMake(8, self.bounds.size.height - 14, self.bounds.size.width - 16, 12)];
        _st.font = [UIFont systemFontOfSize:9];
        _st.textColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:0.7];
        _st.text = @"ready";
        [self addSubview:_st];
    }
    return self;
}

- (UIButton *)btn:(NSString *)t act:(SEL)a f:(CGRect)f {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = f; b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [b setTitle:t forState:UIControlStateNormal]; b.tintColor = [UIColor whiteColor];
    [b addTarget:self action:a forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)setStatus:(NSString *)s { _st.text = s; }

- (void)tTap {
    gOn = !gOn;
    if (gOn) {
        [_tBtn setTitle:@"● REC" forState:UIControlStateNormal];
        _tBtn.tintColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
        self.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1].CGColor;
        _st.text = @"capturing...";
    } else {
        [_tBtn setTitle:@"○ OFF" forState:UIControlStateNormal];
        _tBtn.tintColor = [UIColor whiteColor];
        self.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:0.6].CGColor;
        _st.text = @"stopped";
    }
}

- (void)lTap {
    _exp = !_exp;
    CGRect s = [UIScreen mainScreen].bounds;
    CGFloat bw = (self.bounds.size.width - 20) / 3;
    if (_exp) {
        CGFloat w = s.size.width - 16;
        self.frame = CGRectMake(8, 60, w, s.size.height - 120);
        _tv.hidden = NO;
        _tv.frame = CGRectMake(4, 50, w - 8, self.bounds.size.height - 68);
        _st.frame = CGRectMake(8, self.bounds.size.height - 14, w - 16, 12);
        [self refresh];
    } else {
        self.frame = CGRectMake(30, s.size.height - 164, s.size.width - 60, 44);
        _tv.hidden = YES;
        _st.frame = CGRectMake(8, 30, self.bounds.size.width - 16, 12);
    }
    // relayout buttons
    _tBtn.frame = CGRectMake(5, 2, bw, 40);
    _lBtn.frame = CGRectMake(10+bw, 2, bw, 40);
    _cBtn.frame = CGRectMake(15+bw*2, 2, bw, 40);
}

- (void)cTap {
    @synchronized(entries) { [entries removeAllObjects]; }
    _tv.text = @"";
}

- (void)refresh {
    @synchronized(entries) {
        _tv.text = [entries componentsJoinedByString:@""];
    }
    if (_tv.text.length > 0) [_tv scrollRangeToVisible:NSMakeRange(_tv.text.length - 1, 1)];
    NSUInteger n = entries.count;
    _st.text = n > 0 ? [NSString stringWithFormat:@"%lu entries", (unsigned long)n] : @"ready";
}

- (void)pan:(UIPanGestureRecognizer *)p {
    if (_exp) return;
    CGPoint t = [p translationInView:self];
    self.center = CGPointMake(self.center.x + t.x, self.center.y + t.y);
    [p setTranslation:CGPointZero inView:self];
}
@end

// ========== SSL Pinning 绕过 (runtime swizzle) ==========
static BOOL hookMethod(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    SEL newSel = NSSelectorFromString([NSString stringWithFormat:@"__jqty_%@", NSStringFromSelector(sel)]);
    class_addMethod(cls, newSel, newImp, method_getTypeEncoding(m));
    Method newM = class_getInstanceMethod(cls, newSel);
    method_exchangeImplementations(m, newM);
    if (oldImp) *oldImp = method_getImplementation(newM);
    return YES;
}
static BOOL hookClassMethod(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    return hookMethod(object_getClass(cls), sel, newImp, oldImp);
}

static IMP od_eval, od_pol, ow_eval, oum_jb;
static BOOL hk_eval(id s, SEL c, SecTrustRef t, NSString *d) { return YES; }
static id hk_pol(Class c, SEL s, NSInteger m) {
    id p = ((id(*)(Class, SEL, NSInteger))od_pol)(c, s, m);
    @try { [p setValue:@YES forKey:@"allowInvalidCertificates"]; [p setValue:@NO forKey:@"validatesDomainName"]; [p setValue:@(0) forKey:@"SSLPinningMode"]; } @catch(...){}
    return p;
}
static BOOL hk_weval(id s, SEL c, SecTrustRef t, NSString *d) { return YES; }
static BOOL hk_umjb(Class c, SEL s) { return NO; }

// ========== 入口 ==========
static JQTYWin *gWin;

__attribute__((constructor))
static void init(void) {
    entries = [NSMutableArray array];
    
    // 注册 NSURLProtocol（尽早）
    [NSURLProtocol registerClass:[JQTYProtocol class]];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        Class dc = NSClassFromString(@"DCAFSecurityPolicy");
        if (dc) { hookMethod(dc, @selector(evaluateServerTrust:forDomain:), (IMP)hk_eval, &od_eval); hookClassMethod(dc, @selector(policyWithPinningMode:), (IMP)hk_pol, &od_pol); }
        Class wk = NSClassFromString(@"WPKAFSecurityPolicy");
        if (wk) hookMethod(wk, @selector(evaluateServerTrust:forDomain:), (IMP)hk_weval, &ow_eval);
        Class um = NSClassFromString(@"UMConfigure");
        if (um) hookClassMethod(um, @selector(isJailbreak), (IMP)hk_umjb, &oum_jb);
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        gWin = [[JQTYWin alloc] init];
        gRefresh = ^{ [gWin refresh]; };
    });
}
