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

// ========== 数据存储 ==========
#define MAX_ENTRIES 500
static NSMutableArray *capturedEntries;
static BOOL gCaptureOn = NO;
static void (^gRefreshBlock)(void);

static void storeEntry(NSString *type, NSString *tag, NSData *data) {
    if (!gCaptureOn || !data || data.length == 0) return;
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSString *ts = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                      dateStyle:NSDateFormatterNoStyle
                                                      timeStyle:NSDateFormatterMediumStyle];
        NSMutableString *hex = [NSMutableString string];
        const uint8_t *b = (const uint8_t *)data.bytes;
        NSUInteger show = MIN(data.length, 256);
        for (NSUInteger i = 0; i < show; i += 16) {
            [hex appendFormat:@"%04lx  ", (unsigned long)i];
            for (NSUInteger j = 0; j < 16 && (i+j) < show; j++)
                [hex appendFormat:@"%02x ", b[i+j]];
            [hex appendString:@"\n"];
        }
        if (data.length > 256) [hex appendString:@"...\n"];
        NSString *txt = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSString *body = txt ? txt : hex;
        NSString *entry = [NSString stringWithFormat:@"[%@] %@ %@\n%@\n---\n", ts, type, tag, body];
        @synchronized(capturedEntries) {
            [capturedEntries addObject:entry];
            while (capturedEntries.count > MAX_ENTRIES)
                [capturedEntries removeObjectAtIndex:0];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gRefreshBlock) gRefreshBlock();
        });
    });
}

// ========== NSURLSession Hook ==========
static IMP orig_dataTask;
static id new_dataTask(id self, SEL _cmd, NSURLRequest *req, void (^cb)(NSData *, NSURLResponse *, NSError *)) {
    NSString *tag = [NSString stringWithFormat:@"%@ %@", req.HTTPMethod ?: @"?", req.URL.absoluteString ?: @"?"];
    if (req.HTTPBody) storeEntry(@"REQ", tag, req.HTTPBody);
    void (^nc)(NSData *, NSURLResponse *, NSError *) = ^(NSData *d, NSURLResponse *r, NSError *e) {
        if (d) storeEntry(@"RESP", [NSString stringWithFormat:@"%@ [%ld]", tag, (long)((NSHTTPURLResponse *)r).statusCode], d);
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

// ========== 悬浮窗 ==========
@interface JQTYWindow : UIWindow
- (void)refreshUI;
@end

@implementation JQTYWindow {
    UIButton *_toggleBtn, *_viewBtn, *_clearBtn;
    UITextView *_logView;
    UILabel *_countLabel;
    BOOL _expanded;
}

- (instancetype)init {
    CGRect screen = [UIScreen mainScreen].bounds;
    CGFloat barH = 44;
    self = [super initWithFrame:CGRectMake(30, screen.size.height - barH - 120, screen.size.width - 60, barH)];
    if (self) {
        self.windowLevel = UIWindowLevelAlert + 100;
        self.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.88];
        self.layer.cornerRadius = barH / 2;
        self.layer.masksToBounds = YES;
        self.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:0.6].CGColor;
        self.layer.borderWidth = 1;
        self.hidden = NO;
        
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)];
        [self addGestureRecognizer:pan];
        
        CGFloat bw = (self.bounds.size.width - 20) / 3;
        
        _toggleBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        _toggleBtn.frame = CGRectMake(5, 2, bw, barH - 4);
        _toggleBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [_toggleBtn setTitle:@"● OFF" forState:UIControlStateNormal];
        _toggleBtn.tintColor = [UIColor whiteColor];
        [_toggleBtn addTarget:self action:@selector(tapToggle) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_toggleBtn];
        
        _viewBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        _viewBtn.frame = CGRectMake(10 + bw, 2, bw, barH - 4);
        _viewBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [_viewBtn setTitle:@"LOG" forState:UIControlStateNormal];
        _viewBtn.tintColor = [UIColor whiteColor];
        [_viewBtn addTarget:self action:@selector(tapLog) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_viewBtn];
        
        _clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        _clearBtn.frame = CGRectMake(15 + bw * 2, 2, bw, barH - 4);
        _clearBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [_clearBtn setTitle:@"CLR" forState:UIControlStateNormal];
        _clearBtn.tintColor = [UIColor whiteColor];
        [_clearBtn addTarget:self action:@selector(tapClear) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_clearBtn];
        
        _countLabel = [[UILabel alloc] initWithFrame:CGRectMake(5, 0, 80, 12)];
        _countLabel.font = [UIFont systemFontOfSize:9];
        _countLabel.textColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:0.7];
        [self addSubview:_countLabel];
        
        _logView = [[UITextView alloc] init];
        _logView.backgroundColor = [UIColor colorWithWhite:0.03 alpha:0.95];
        _logView.textColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
        _logView.font = [UIFont fontWithName:@"Courier" size:10] ?: [UIFont systemFontOfSize:10];
        _logView.editable = NO;
        _logView.hidden = YES;
        _logView.layer.cornerRadius = 6;
        _logView.layer.masksToBounds = YES;
        [self addSubview:_logView];
    }
    return self;
}

- (void)tapToggle {
    gCaptureOn = !gCaptureOn;
    if (gCaptureOn) {
        [_toggleBtn setTitle:@"● REC" forState:UIControlStateNormal];
        _toggleBtn.tintColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
        self.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1].CGColor;
    } else {
        [_toggleBtn setTitle:@"○ OFF" forState:UIControlStateNormal];
        _toggleBtn.tintColor = [UIColor whiteColor];
        self.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:0.6].CGColor;
    }
}

- (void)tapLog {
    _expanded = !_expanded;
    CGRect screen = [UIScreen mainScreen].bounds;
    if (_expanded) {
        CGFloat w = screen.size.width - 16;
        self.frame = CGRectMake(8, 60, w, screen.size.height - 120);
        _logView.hidden = NO;
        _logView.frame = CGRectMake(4, 50, w - 8, self.bounds.size.height - 58);
        [self refreshUI];
    } else {
        self.frame = CGRectMake(30, screen.size.height - 164, screen.size.width - 60, 44);
        _logView.hidden = YES;
    }
    [self relayoutButtons];
}

- (void)tapClear {
    @synchronized(capturedEntries) {
        [capturedEntries removeAllObjects];
    }
    _logView.text = @"";
    _countLabel.text = @"0";
}

- (void)refreshUI {
    @synchronized(capturedEntries) {
        _logView.text = [capturedEntries componentsJoinedByString:@""];
    }
    if (_logView.text.length > 0)
        [_logView scrollRangeToVisible:NSMakeRange(_logView.text.length - 1, 1)];
    _countLabel.text = [NSString stringWithFormat:@"%lu", (unsigned long)capturedEntries.count];
}

- (void)relayoutButtons {
    CGFloat bw = (self.bounds.size.width - 20) / 3;
    CGFloat barH = 44;
    _toggleBtn.frame = CGRectMake(5, 2, bw, barH - 4);
    _viewBtn.frame = CGRectMake(10 + bw, 2, bw, barH - 4);
    _clearBtn.frame = CGRectMake(15 + bw * 2, 2, bw, barH - 4);
}

- (void)pan:(UIPanGestureRecognizer *)p {
    if (_expanded) return;
    CGPoint t = [p translationInView:self];
    self.center = CGPointMake(self.center.x + t.x, self.center.y + t.y);
    [p setTranslation:CGPointZero inView:self];
}

@end

// ========== 入口 ==========
static JQTYWindow *gWin;

__attribute__((constructor))
static void init(void) {
    capturedEntries = [NSMutableArray array];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        Class ns = NSClassFromString(@"NSURLSession");
        if (ns) orig_dataTask = swizzleInstance(ns, @selector(dataTaskWithRequest:completionHandler:), (IMP)new_dataTask);
        Class dc = NSClassFromString(@"DCAFSecurityPolicy");
        if (dc) { orig_DCAF_eval = swizzleInstance(dc, @selector(evaluateServerTrust:forDomain:), (IMP)new_DCAF_eval); orig_DCAF_policy = swizzleClass(dc, @selector(policyWithPinningMode:), (IMP)new_DCAF_policy); }
        Class wk = NSClassFromString(@"WPKAFSecurityPolicy");
        if (wk) orig_WPKAF_eval = swizzleInstance(wk, @selector(evaluateServerTrust:forDomain:), (IMP)new_WPKAF_eval);
        Class um = NSClassFromString(@"UMConfigure");
        if (um) orig_UM_jb = swizzleClass(um, @selector(isJailbreak), (IMP)new_UM_jb);
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        gWin = [[JQTYWindow alloc] init];
        gRefreshBlock = ^{ [gWin refreshUI]; };
    });
}
