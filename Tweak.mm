#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ========== Swizzle（改用 exchange 更可靠） ==========
static BOOL hookMethod(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        NSLog(@"[JQTY] HOOK FAIL: class_getInstanceMethod nil for %@ %@", cls, NSStringFromSelector(sel));
        return NO;
    }
    IMP orig = method_getImplementation(m);
    if (orig == newImp) {
        NSLog(@"[JQTY] HOOK SKIP: already hooked %@ %@", cls, NSStringFromSelector(sel));
        return NO;
    }
    // 先加个新方法，再 exchange
    SEL newSel = NSSelectorFromString([NSString stringWithFormat:@"__jqty_%@", NSStringFromSelector(sel)]);
    const char *types = method_getTypeEncoding(m);
    class_addMethod(cls, newSel, newImp, types);
    Method newM = class_getInstanceMethod(cls, newSel);
    method_exchangeImplementations(m, newM);
    if (oldImp) *oldImp = method_getImplementation(newM); // exchange 后 newM 持有原始 IMP
    NSLog(@"[JQTY] HOOK OK: %@ %@ old=%p new=%p", cls, NSStringFromSelector(sel), *oldImp, method_getImplementation(m));
    return YES;
}

static BOOL hookClassMethod(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    return hookMethod(object_getClass(cls), sel, newImp, oldImp);
}

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
        @synchronized(entries) {
            [entries addObject:e];
            while (entries.count > MAX_ENTRIES) [entries removeObjectAtIndex:0];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ if (gRefresh) gRefresh(); });
    });
}

// ========== NSURLSession Hook ==========
static IMP orig_dataTask;

static id hook_dataTask(id self, SEL _cmd, NSURLRequest *req, void (^cb)(NSData *, NSURLResponse *, NSError *)) {
    NSString *url = req.URL.absoluteString ?: @"";
    NSLog(@"[JQTY] >>> NSURLSession dataTask: %@ %@", req.HTTPMethod, url);
    if (req.HTTPBody) store(@"REQ", url, req.HTTPBody);
    void (^nc)(NSData *, NSURLResponse *, NSError *) = ^(NSData *d, NSURLResponse *r, NSError *err) {
        if (d && d.length > 0) {
            NSInteger sc = [(NSHTTPURLResponse *)r statusCode];
            store(@"RESP", [NSString stringWithFormat:@"%@ [%ld]", url, (long)sc], d);
            NSLog(@"[JQTY] <<< RESP %@ [%ld] %luB", url, (long)sc, (unsigned long)d.length);
        }
        if (cb) cb(d, r, err);
    };
    return ((id (*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))orig_dataTask)(self, _cmd, req, nc);
}

// ========== SSL Pinning 绕过 ==========
static IMP orig_DCAF_eval, orig_DCAF_policy, orig_WPKAF_eval, orig_UM_jb;
static BOOL hook_DCAF_eval(id s, SEL c, SecTrustRef t, NSString *d) {
    NSLog(@"[JQTY] DCAFSecurityPolicy evaluateServerTrust bypassed");
    return YES;
}
static id hook_DCAF_policy(Class cls, SEL _c, NSInteger m) {
    id p = ((id(*)(Class, SEL, NSInteger))orig_DCAF_policy)(cls, _c, m);
    @try { [p setValue:@YES forKey:@"allowInvalidCertificates"]; [p setValue:@NO forKey:@"validatesDomainName"]; [p setValue:@(0) forKey:@"SSLPinningMode"]; } @catch(...){}
    NSLog(@"[JQTY] DCAFSecurityPolicy policyWithPinningMode bypassed mode=%ld", (long)m);
    return p;
}
static BOOL hook_WPKAF_eval(id s, SEL c, SecTrustRef t, NSString *d) { return YES; }
static BOOL hook_UM_jb(Class c, SEL s) { NSLog(@"[JQTY] UMConfigure isJailbreak -> NO"); return NO; }

// ========== 悬浮窗 ==========
@interface JQTYWin : UIWindow
- (void)refresh;
@end

@implementation JQTYWin {
    UIButton *_tBtn, *_lBtn, *_cBtn;
    UITextView *_tv;
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
        _tBtn = [self makeBtn:@"● OFF" act:@selector(tTap) frame:CGRectMake(5, 2, bw, 40)];
        _lBtn = [self makeBtn:@"LOG" act:@selector(lTap) frame:CGRectMake(10+bw, 2, bw, 40)];
        _cBtn = [self makeBtn:@"CLR" act:@selector(cTap) frame:CGRectMake(15+bw*2, 2, bw, 40)];
        [self addSubview:_tBtn]; [self addSubview:_lBtn]; [self addSubview:_cBtn];

        _tv = [[UITextView alloc] init];
        _tv.backgroundColor = [UIColor colorWithWhite:0.03 alpha:0.95];
        _tv.textColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
        _tv.font = [UIFont fontWithName:@"Courier" size:10] ?: [UIFont systemFontOfSize:10];
        _tv.editable = NO; _tv.hidden = YES;
        [self addSubview:_tv];
    }
    return self;
}

- (UIButton *)makeBtn:(NSString *)t act:(SEL)a frame:(CGRect)f {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = f; b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [b setTitle:t forState:UIControlStateNormal]; b.tintColor = [UIColor whiteColor];
    [b addTarget:self action:a forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)tTap {
    gOn = !gOn;
    if (gOn) {
        [_tBtn setTitle:@"● REC" forState:UIControlStateNormal];
        _tBtn.tintColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
        self.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1].CGColor;
        NSLog(@"[JQTY] CAPTURE ON");
    } else {
        [_tBtn setTitle:@"○ OFF" forState:UIControlStateNormal];
        _tBtn.tintColor = [UIColor whiteColor];
        self.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:0.6].CGColor;
        NSLog(@"[JQTY] CAPTURE OFF");
    }
}

- (void)lTap {
    _exp = !_exp;
    CGRect s = [UIScreen mainScreen].bounds;
    CGFloat bw = (self.bounds.size.width - 20) / 3;
    if (_exp) {
        CGFloat w = s.size.width - 16;
        self.frame = CGRectMake(8, 60, w, s.size.height - 120);
        _tv.hidden = NO; _tv.frame = CGRectMake(4, 50, w - 8, self.bounds.size.height - 58);
        [self refresh];
    } else {
        self.frame = CGRectMake(30, s.size.height - 164, s.size.width - 60, 44);
        _tv.hidden = YES;
    }
}

- (void)cTap {
    @synchronized(entries) { [entries removeAllObjects]; }
    _tv.text = @"";
    NSLog(@"[JQTY] LOG CLEARED");
}

- (void)refresh {
    @synchronized(entries) {
        _tv.text = [entries componentsJoinedByString:@""];
    }
    if (_tv.text.length > 0) [_tv scrollRangeToVisible:NSMakeRange(_tv.text.length - 1, 1)];
}

- (void)pan:(UIPanGestureRecognizer *)p {
    if (_exp) return;
    CGPoint t = [p translationInView:self];
    self.center = CGPointMake(self.center.x + t.x, self.center.y + t.y);
    [p setTranslation:CGPointZero inView:self];
}
@end

// ========== 入口 ==========
static JQTYWin *gWin;

__attribute__((constructor))
static void init(void) {
    NSLog(@"[JQTY] ===== dylib loaded =====");
    entries = [NSMutableArray array];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSLog(@"[JQTY] --- installing hooks ---");
        
        BOOL ok1 = hookMethod(NSClassFromString(@"NSURLSession"),
                              @selector(dataTaskWithRequest:completionHandler:),
                              (IMP)hook_dataTask, &orig_dataTask);
        NSLog(@"[JQTY] NSURLSession hook: %@", ok1 ? @"YES" : @"NO");
        
        Class dc = NSClassFromString(@"DCAFSecurityPolicy");
        if (dc) {
            hookMethod(dc, @selector(evaluateServerTrust:forDomain:), (IMP)hook_DCAF_eval, &orig_DCAF_eval);
            hookClassMethod(dc, @selector(policyWithPinningMode:), (IMP)hook_DCAF_policy, &orig_DCAF_policy);
        }
        Class wk = NSClassFromString(@"WPKAFSecurityPolicy");
        if (wk) hookMethod(wk, @selector(evaluateServerTrust:forDomain:), (IMP)hook_WPKAF_eval, &orig_WPKAF_eval);
        Class um = NSClassFromString(@"UMConfigure");
        if (um) hookClassMethod(um, @selector(isJailbreak), (IMP)hook_UM_jb, &orig_UM_jb);
        
        NSLog(@"[JQTY] --- hooks done ---");
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSLog(@"[JQTY] --- creating window ---");
        gWin = [[JQTYWin alloc] init];
        gRefresh = ^{ [gWin refresh]; };
        NSLog(@"[JQTY] --- window created ---");
    });
}
