//
//  AppDelegate.m — menu bar: flag only (Tor exit country from pref pane); IP in menu when opened.
//

#import "AppDelegate.h"
#import <AppKit/AppKit.h>

static NSString *IPCMBSharedExitIdentityPath(void)
{
    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/IPChanger"];
    return [dir stringByAppendingPathComponent:@"exit-identity.plist"];
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

/// NSStatusItem titles often render regional-indicator flags as blank; rasterize like the pref pane does.
static NSImage *IPCMBRasterizeFlagEmoji(NSString *emoji)
{
    NSString *s = emoji.length ? emoji : @"🌐";
    CGFloat fontSize = 17.0;
    NSFont *font = [NSFont fontWithName:@"Apple Color Emoji" size:fontSize];
    if (!font) {
        font = [NSFont systemFontOfSize:fontSize];
    }
    NSMutableParagraphStyle *para = [[NSMutableParagraphStyle alloc] init];
    para.alignment = NSTextAlignmentCenter;
    NSDictionary *attrs = @{
        NSFontAttributeName: font,
        NSParagraphStyleAttributeName: para,
    };
    NSStringDrawingOptions drawOpts = NSStringDrawingUsesLineFragmentOrigin | NSStringDrawingUsesDeviceMetrics;
    NSSize maxHint = NSMakeSize(120.0, 90.0);
    NSRect br = [s boundingRectWithSize:maxHint options:drawOpts attributes:attrs];
    CGFloat tw = MAX(18.0, ceil(NSWidth(br)));
    CGFloat th = MAX(16.0, ceil(NSHeight(br)));
    NSSize sz = NSMakeSize(tw + 10.0, th + 8.0);

    NSImage *image = [NSImage imageWithSize:sz flipped:NO drawingHandler:^BOOL(NSRect rect) {
        [[NSGraphicsContext currentContext] setImageInterpolation:NSImageInterpolationHigh];
        [[NSColor clearColor] setFill];
        NSRectFill(rect);
        CGFloat x = floor((NSWidth(rect) - tw) * 0.5);
        CGFloat y = floor((NSHeight(rect) - th) * 0.5);
        NSRect drawR = NSMakeRect(x, y, tw, th);
        [s drawWithRect:drawR options:drawOpts attributes:attrs context:nil];
        return YES;
    }];
    image.template = NO;
    // Status bar layout expects a modest logical size.
    [image setSize:NSMakeSize(22.0, 18.0)];
    return image;
}

@interface AppDelegate () <NSMenuDelegate>
@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) NSTimer *pollTimer;
@property (nonatomic, strong) NSMenuItem *ipMenuItem;
@property (nonatomic, strong) NSMenuItem *detailMenuItem;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    NSButton *btn = self.statusItem.button;
    btn.image = IPCMBRasterizeFlagEmoji(@"🌐");
    btn.imagePosition = NSImageOnly;
    btn.title = @"";

    NSMenu *menu = [[NSMenu alloc] init];
    menu.delegate = self;

    self.ipMenuItem = [[NSMenuItem alloc] initWithTitle:@"IP: —" action:NULL keyEquivalent:@""];
    self.ipMenuItem.enabled = NO;

    self.detailMenuItem = [[NSMenuItem alloc] initWithTitle:@"" action:NULL keyEquivalent:@""];
    self.detailMenuItem.enabled = NO;
    self.detailMenuItem.hidden = YES;

    [menu addItem:self.ipMenuItem];
    [menu addItem:self.detailMenuItem];
    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *m;
    m = [menu addItemWithTitle:@"Reload from IP Changer" action:@selector(reloadFromSharedState) keyEquivalent:@"r"];
    m.target = self;

    m = [menu addItemWithTitle:@"Open IP Changer Settings…" action:@selector(openSystemSettingsForIPChanger) keyEquivalent:@"s"];
    m.target = self;

    [menu addItem:[NSMenuItem separatorItem]];

    m = [menu addItemWithTitle:@"Quit IP Changer Menu" action:@selector(quit) keyEquivalent:@"q"];
    m.target = self;

    self.statusItem.menu = menu;

    [[NSDistributedNotificationCenter defaultCenter] addObserver:self selector:@selector(reloadFromSharedState) name:@"com.philodi.ipchanger.ExitIdentityChanged" object:nil suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];

    [self reloadFromSharedState];
    __weak typeof(self) wself = self;
    self.pollTimer = [NSTimer timerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *timer) {
        [wself reloadFromSharedState];
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.pollTimer forMode:NSRunLoopCommonModes];
}

- (void)dealloc
{
    [[NSDistributedNotificationCenter defaultCenter] removeObserver:self name:@"com.philodi.ipchanger.ExitIdentityChanged" object:nil];
}

- (void)menuWillOpen:(NSMenu *)menu
{
    [self reloadFromSharedState];
}

/// Reads `~/Library/Application Support/IPChanger/exit-identity.plist` written by the pref pane (Tor exit lookup).
- (void)reloadFromSharedState
{
    NSString *path = IPCMBSharedExitIdentityPath();
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:path];

    NSString *ip = @"";
    NSString *cc = @"";
    NSString *country = @"";
    NSString *city = @"";
    BOOL ok = NO;

    if ([plist isKindOfClass:[NSDictionary class]]) {
        ok = [plist[@"ok"] boolValue];
        id q = plist[@"query"];
        ip = ([q isKindOfClass:[NSString class]]) ? (NSString *)q : @"";
        id c = plist[@"countryCode"];
        cc = ([c isKindOfClass:[NSString class]]) ? (NSString *)c : @"";
        id co = plist[@"country"];
        country = ([co isKindOfClass:[NSString class]]) ? (NSString *)co : @"";
        id ci = plist[@"city"];
        city = ([ci isKindOfClass:[NSString class]]) ? (NSString *)ci : @"";
    }

    NSString *flag = IPCMBFlagEmojiFromCountryCode(cc);
    if (!flag.length) {
        flag = @"🌐";
    }

    NSButton *barBtn = self.statusItem.button;
    barBtn.image = IPCMBRasterizeFlagEmoji(flag);
    barBtn.imagePosition = NSImageOnly;
    barBtn.title = @"";

    self.ipMenuItem.title = ip.length ? [NSString stringWithFormat:@"IP: %@", ip] : @"IP: —";

    NSMutableString *detail = [NSMutableString string];
    if (city.length && country.length) {
        [detail appendFormat:@"%@, %@", city, country];
    } else if (country.length) {
        [detail appendString:country];
    } else if (!ok && ip.length) {
        [detail appendString:@"Geo unavailable (check Tor SOCKS in IP Changer)"];
    }
    if (detail.length) {
        self.detailMenuItem.title = [detail copy];
        self.detailMenuItem.hidden = NO;
    } else {
        self.detailMenuItem.title = @"";
        self.detailMenuItem.hidden = YES;
    }

    NSMutableString *tip = [NSMutableString string];
    if (ip.length) [tip appendFormat:@"IP: %@", ip];
    if (ok && country.length) {
        if (tip.length) [tip appendString:@"\n"];
        [tip appendString:country];
        if (city.length) [tip appendFormat:@" — %@", city];
    } else if (ip.length && !ok) {
        if (tip.length) [tip appendString:@"\n"];
        [tip appendString:@"Open IP Changer for Tor exit details."];
    }
    if (!tip.length) {
        [tip appendString:@"Open IP Changer in System Settings — exit identity appears after the pane refreshes."];
    }
    self.statusItem.button.toolTip = [tip copy];
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

    if (paneURL && [[NSWorkspace sharedWorkspace] openURL:paneURL]) {
        return;
    }

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
