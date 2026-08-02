#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ========== NSURLProtocol 网络拦截 ==========
@interface JQTYProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic) NSURLSessionDataTask *task;
@property (nonatomic) NSMutableData *respData;
@end

@implementation JQTYProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"JQTY" inRequest:request]) return NO;
    return YES;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"JQTY" inRequest:req];
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    cfg.protocolClasses = @[];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.task = [s dataTaskWithRequest:req];
    self.respData = [NSMutableData data];
    [self.task resume];
    
    // 通知 UI
    NSString *url = req.URL.absoluteString ?: @"";
    [[NSNotificationCenter defaultCenter] postNotificationName:@"JQTYRequest"
                                                        object:nil
                                                      userInfo:@{@"url": url, @"method": req.HTTPMethod ?: @"GET", @"body": req.HTTPBody ?: [NSData data]}];
}

- (void)stopLoading { [self.task cancel]; }
- (void)URLSession:(NSURLSession *)s dataTask:(NSURLSessionDataTask *)t didReceiveData:(NSData *)d {
    [self.respData appendData:d]; [self.client URLProtocol:self didLoadData:d];
}
- (void)URLSession:(NSURLSession *)s dataTask:(NSURLSessionDataTask *)t didReceiveResponse:(NSURLResponse *)r completionHandler:(void (^)(NSURLSessionResponseDisposition))h {
    [self.client URLProtocol:self didReceiveResponse:r cacheStoragePolicy:NSURLCacheStorageNotAllowed]; h(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)s task:(NSURLSessionTask *)t didCompleteWithError:(NSError *)e {
    if (e) [self.client URLProtocol:self didFailWithError:e];
    else {
        [[NSNotificationCenter defaultCenter] postNotificationName:@"JQTYResponse"
                                                            object:nil
                                                          userInfo:@{@"url": self.request.URL.absoluteString ?: @"",
                                                                     @"code": @(((NSHTTPURLResponse *)t.response).statusCode),
                                                                     @"data": self.respData}];
        [self.client URLProtocolDidFinishLoading:self];
    }
}
@end

// ========== ViewController ==========
@interface ViewController : UIViewController <UITextViewDelegate>
@end

@implementation ViewController {
    UISwitch *_sw;
    UITextView *_log;
    UILabel *_count;
    NSMutableArray *_entries;
    BOOL _capturing;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.06 alpha:1];
    _entries = [NSMutableArray array];
    
    CGFloat w = self.view.bounds.size.width;
    
    // 标题
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, w - 40, 30)];
    title.text = @"JQTY Packet Capture"; title.font = [UIFont boldSystemFontOfSize:18];
    title.textColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
    [self.view addSubview:title];
    
    // 开关
    UILabel *swLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 100, 200, 30)];
    swLabel.text = @"Capture"; swLabel.textColor = [UIColor whiteColor]; swLabel.font = [UIFont systemFontOfSize:16];
    [self.view addSubview:swLabel];
    
    _sw = [[UISwitch alloc] initWithFrame:CGRectMake(w - 70, 100, 0, 0)];
    _sw.onTintColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
    [_sw addTarget:self action:@selector(toggleCapture) forControlEvents:UIControlEventValueChanged];
    [self.view addSubview:_sw];
    
    // 计数
    _count = [[UILabel alloc] initWithFrame:CGRectMake(20, 140, w - 40, 20)];
    _count.text = @"0 requests"; _count.textColor = [UIColor grayColor]; _count.font = [UIFont systemFontOfSize:12];
    [self.view addSubview:_count];
    
    // 清空按钮
    UIButton *clr = [UIButton buttonWithType:UIButtonTypeSystem];
    clr.frame = CGRectMake(w - 80, 137, 60, 26);
    [clr setTitle:@"Clear" forState:UIControlStateNormal];
    clr.tintColor = [UIColor colorWithRed:1 green:0.3 blue:0.3 alpha:1];
    [clr addTarget:self action:@selector(clear) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:clr];
    
    // 日志区
    _log = [[UITextView alloc] initWithFrame:CGRectMake(10, 170, w - 20, self.view.bounds.size.height - 190)];
    _log.backgroundColor = [UIColor colorWithWhite:0.03 alpha:1];
    _log.textColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1];
    _log.font = [UIFont fontWithName:@"Courier" size:10] ?: [UIFont systemFontOfSize:10];
    _log.editable = NO;
    _log.layer.cornerRadius = 8;
    _log.layer.masksToBounds = YES;
    _log.layer.borderColor = [UIColor colorWithRed:0 green:1 blue:0.5 alpha:0.3].CGColor;
    _log.layer.borderWidth = 1;
    [self.view addSubview:_log];
    
    // 监听网络事件
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(onReq:) name:@"JQTYRequest" object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(onResp:) name:@"JQTYResponse" object:nil];
}

- (void)toggleCapture {
    _capturing = _sw.isOn;
    _count.text = _capturing ? @"0 requests (capturing...)" : @"0 requests (stopped)";
    _count.textColor = _capturing ? [UIColor colorWithRed:0 green:1 blue:0.5 alpha:1] : [UIColor grayColor];
}

- (void)onReq:(NSNotification *)n {
    if (!_capturing) return;
    NSString *url = n.userInfo[@"url"];
    NSString *method = n.userInfo[@"method"];
    NSData *body = n.userInfo[@"body"];
    [self addEntry:[NSString stringWithFormat:@"REQ %@ %@\n", method, url]];
    if (body.length > 0) {
        NSString *txt = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        [self addEntry:txt ?: [self hex:body]];
    }
}

- (void)onResp:(NSNotification *)n {
    if (!_capturing) return;
    NSString *url = n.userInfo[@"url"];
    NSNumber *code = n.userInfo[@"code"];
    NSData *data = n.userInfo[@"data"];
    [self addEntry:[NSString stringWithFormat:@"RESP [%@] %@\n", code, url]];
    if (data.length > 0) {
        NSString *txt = [[NSString alloc] initWithData:[data subdataWithRange:NSMakeRange(0, MIN(2000, data.length))] encoding:NSUTF8StringEncoding];
        [self addEntry:txt ?: [self hex:[data subdataWithRange:NSMakeRange(0, MIN(256, data.length))]]];
    }
    [self addEntry:@"---\n"];
}

- (NSString *)hex:(NSData *)d {
    NSMutableString *s = [NSMutableString string];
    const uint8_t *b = d.bytes;
    for (NSUInteger i = 0; i < d.length; i += 16) {
        [s appendFormat:@"%04lx  ", (unsigned long)i];
        for (NSUInteger j = 0; j < 16 && (i+j) < d.length; j++) [s appendFormat:@"%02x ", b[i+j]];
        [s appendString:@"\n"];
    }
    return s;
}

- (void)addEntry:(NSString *)e {
    dispatch_async(dispatch_get_main_queue(), ^{
        [_entries addObject:e];
        if (_entries.count > 500) [_entries removeObjectAtIndex:0];
        _log.text = [_entries componentsJoinedByString:@""];
        [_log scrollRangeToVisible:NSMakeRange(_log.text.length - 1, 1)];
        _count.text = [NSString stringWithFormat:@"%lu requests %@", (unsigned long)(_entries.count / 2), _capturing ? @"(capturing...)" : @"(stopped)"];
    });
}

- (void)clear {
    [_entries removeAllObjects];
    _log.text = @"";
    _count.text = _capturing ? @"0 requests (capturing...)" : @"0 requests (stopped)";
}

- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }
@end

// ========== AppDelegate ==========
@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opt {
    [NSURLProtocol registerClass:[JQTYProtocol class]];
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[ViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

// ========== main ==========
int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
