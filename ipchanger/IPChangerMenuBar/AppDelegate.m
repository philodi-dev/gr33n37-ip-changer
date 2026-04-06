//
//  AppDelegate.m — menu bar: public IP + country flag; opens IP Changer pref pane in System Settings.
//

#import "AppDelegate.h"
#import <AppKit/AppKit.h>

static NSString *IPCMBCurlDirect(NSString *url)
{
    NSArray *args = @[
        @"-s", @"--connect-timeout", @"6", @"-m", @"10",
        url,
    ];
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/curl"];
    task.arguments = args;
    task.standardError = [NSFileHandle fileHandleForWritingAtPath:@"/dev/null"];
    NSPipe *out = [NSPipe pipe];
    task.standardOutput = out;
    @try {
        [task launch];
    } @catch (__unused NSException *ex) {
        return nil;
    }
    [task waitUntilExit];
    NSData *data = [[out fileHandleForReading] readDataToEndOfFile];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

/// ISO 3166-1 alpha-2 → regional-indicator flag emoji (empty if invalid).
static NSString *IPCMBFlagEmojiFromCountryCode(NSString *cc)
{
    if (cc.length != 2) return @"";
    unichar a = (unichar)toupper([cc characterAtIndex:0]);
    unichar b = (unichar)toupper([cc characterAtIndex:1]);
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return @"";
    unichar r0 = (unichar)(0x1F1E6 + (a - 'A'));
    unichar r1 = (unichar)(0x1F1E6 + (b - 'A'));
    return [NSString stringWithCharacters:(unichar[]){ r0, r1 } length:2];
}

@interface AppDelegate ()
@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) NSTimer *refreshTimer;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    NSButton *btn = self.statusItem.button;
    btn.image = nil;
    btn.imagePosition = NSNoImage;
    btn.title = @"…";

    NSMenu *menu = [[NSMenu alloc] init];
    NSMenuItem *m;

    m = [menu addItemWithTitle:@"Refresh now" action:@selector(refreshNow) keyEquivalent:@"r"];
    m.target = self;

    m = [menu addItemWithTitle:@"Open IP Changer Settings…" action:@selector(openSystemSettingsForIPChanger) keyEquivalent:@"s"];
    m.target = self;

    [menu addItem:[NSMenuItem separatorItem]];

    m = [menu addItemWithTitle:@"Quit IP Changer Menu" action:@selector(quit) keyEquivalent:@"q"];
    m.target = self;

    self.statusItem.menu = menu;

    [self refreshNow];
    __weak typeof(self) wself = self;
    self.refreshTimer = [NSTimer timerWithTimeInterval:30.0 repeats:YES block:^(NSTimer *timer) {
        [wself refreshNow];
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.refreshTimer forMode:NSRunLoopCommonModes];
}

- (void)refreshNow
{
    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;

        // Direct connection (not Tor SOCKS) so the menu bar shows your public IP + geo when online.
        NSString *json = IPCMBCurlDirect(@"http://ip-api.com/json/?fields=status,message,query,country,countryCode,city");
        NSString *title = @"—";
        NSString *tip = @"Could not reach ip-api.com. Check your network.";

        if (json.length) {
            NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
            if ([dict isKindOfClass:[NSDictionary class]] && [dict[@"status"] isEqualToString:@"success"]) {
                NSString *city = [dict[@"city"] isKindOfClass:[NSString class]] ? dict[@"city"] : @"";
                NSString *country = [dict[@"country"] isKindOfClass:[NSString class]] ? dict[@"country"] : @"";
                NSString *cc = [dict[@"countryCode"] isKindOfClass:[NSString class]] ? dict[@"countryCode"] : @"";
                NSString *query = [dict[@"query"] isKindOfClass:[NSString class]] ? dict[@"query"] : @"";
                NSString *flag = IPCMBFlagEmojiFromCountryCode(cc);
                if (query.length) {
                    title = flag.length ? [NSString stringWithFormat:@"%@ %@", flag, query] : [query copy];
                }
                NSMutableString *detail = [NSMutableString string];
                if (query.length) [detail appendFormat:@"IP: %@\n", query];
                if (city.length && country.length) {
                    [detail appendFormat:@"%@, %@ (%@)", city, country, cc.uppercaseString];
                } else if (country.length) {
                    [detail appendFormat:@"%@ (%@)", country, cc.uppercaseString];
                }
                tip = detail.length ? [detail copy] : tip;
            } else if ([dict isKindOfClass:[NSDictionary class]] && [dict[@"message"] isKindOfClass:[NSString class]]) {
                tip = dict[@"message"];
            }
        }

        // Fallback: IP only (no geo)
        if ([title isEqualToString:@"—"] || !title.length) {
            NSString *plain = IPCMBCurlDirect(@"https://checkip.amazonaws.com");
            NSString *ip = [plain stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (ip.length) {
                title = ip;
                tip = [NSString stringWithFormat:@"IP: %@", ip];
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self2 = weakSelf;
            if (!self2) return;
            self2.statusItem.button.title = title;
            self2.statusItem.button.toolTip = tip;
        });
    });
}

- (void)openSystemSettingsForIPChanger
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *homePP = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/PreferencePanes/ipchanger.prefPane"];
    NSString *sysPP = @"/Library/PreferencePanes/ipchanger.prefPane";
    NSURL *paneURL = nil;
    if ([fm fileExistsAtPath:homePP]) {
        paneURL = [NSURL fileURLWithPath:homePP isDirectory:YES];
    } else if ([fm fileExistsAtPath:sysPP]) {
        paneURL = [NSURL fileURLWithPath:sysPP isDirectory:YES];
    }

    // Opening the .prefPane bundle is the most reliable way to focus the IP Changer pane.
    if (paneURL && [[NSWorkspace sharedWorkspace] openURL:paneURL]) {
        return;
    }

    // Requires NSPrefPaneAllowsXAppleSystemPreferencesURLScheme in the pref pane Info.plist (set in this repo).
    NSURL *scheme = [NSURL URLWithString:@"x-apple.systempreferences:com.philodi.ipchanger"];
    if ([[NSWorkspace sharedWorkspace] openURL:scheme]) {
        return;
    }

    NSURL *settingsApp = [NSURL fileURLWithPath:@"/System/Applications/System Settings.app" isDirectory:YES];
    [[NSWorkspace sharedWorkspace] openURL:settingsApp];
}

- (void)quit
{
    [NSApp terminate:nil];
}

@end
