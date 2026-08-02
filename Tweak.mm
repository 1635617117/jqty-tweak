#import <Foundation/Foundation.h>

__attribute__((constructor))
static void test(void) {
    // 用 NSLog 汇报每一步
    NSLog(@"[JQTY] dylib loaded");
    
    // 方案1: App 自己的 Documents
    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *p1 = [doc stringByAppendingPathComponent:@"jqty_test.txt"];
    
    // 方案2: App 自己的 tmp
    NSString *p2 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"jqty_test.txt"];
    
    // 方案3: /tmp
    NSString *p3 = @"/tmp/jqty_test.txt";
    
    NSArray *paths = @[p1, p2, p3];
    for (NSString *p in paths) {
        NSError *err = nil;
        BOOL ok = [@"JQTYPacketLog test write\n" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:&err];
        if (ok) {
            NSLog(@"[JQTY] OK: %@", p);
        } else {
            NSLog(@"[JQTY] FAIL: %@ error=%@", p, err.localizedDescription);
        }
    }
}
