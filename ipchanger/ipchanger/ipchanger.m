//
//  ipchanger.m
//  ipchanger
//
//  Tor IP rotation — mirrors ip-changer.sh / README usage on macOS.
//

#import "ipchanger.h"
#import <AppKit/AppKit.h>
#import <Network/Network.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>

static NSString * const kTorSOCKSHost = @"127.0.0.1";
static const in_port_t kTorSOCKSPort = 9050;
static const in_port_t kTorControlPort = 9051;

static NSString *IPCHexEncodeData(NSData *data)
{
    if (data.length == 0) return @"";
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    const uint8_t *b = data.bytes;
    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", b[i]];
    }
    return hex;
}

static NSMutableString *IPCTorControlPayloadWithAuth(void)
{
    NSArray<NSString *> *cookiePaths = @[
        @"/opt/homebrew/var/lib/tor/control_auth_cookie",
        @"/usr/local/var/lib/tor/control_auth_cookie",
        [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/Tor/control_auth_cookie"],
    ];

    NSData *cookie = nil;
    for (NSString *p in cookiePaths) {
        if ([[NSFileManager defaultManager] isReadableFileAtPath:p]) {
            cookie = [NSData dataWithContentsOfFile:p];
            if (cookie.length > 0) break;
        }
    }

    NSMutableString *payload = [NSMutableString string];
    if (cookie.length > 0) {
        [payload appendFormat:@"AUTHENTICATE %@\r\n", IPCHexEncodeData(cookie)];
    } else {
        [payload appendString:@"AUTHENTICATE \"\"\r\n"];
    }
    return payload;
}

/// Sends a full control script (must include AUTH) and returns the ASCII reply after Tor closes the connection.
static NSString *IPCTorControlExchange(NSString *payload, NSError **outError)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"ipchanger" code:100 userInfo:@{ NSLocalizedDescriptionKey: @"Could not open socket for Tor control port." }];
        }
        return nil;
    }

    struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, (socklen_t)sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kTorControlPort);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        if (outError) {
            *outError = [NSError errorWithDomain:@"ipchanger" code:101 userInfo:@{ NSLocalizedDescriptionKey: @"Tor control port not reachable (127.0.0.1:9051). Enable ControlPort in torrc, or rotation will fall back to restarting the service." }];
        }
        return nil;
    }

    const char *bytes = payload.UTF8String;
    size_t len = strlen(bytes);
    if (send(fd, bytes, len, 0) < 0) {
        close(fd);
        if (outError) {
            *outError = [NSError errorWithDomain:@"ipchanger" code:102 userInfo:@{ NSLocalizedDescriptionKey: @"Failed to write to Tor control port." }];
        }
        return nil;
    }

    NSMutableData *accum = [NSMutableData data];
    char rbuf[8192];
    ssize_t n;
    while ((n = recv(fd, rbuf, (int)sizeof(rbuf), 0)) > 0) {
        [accum appendBytes:rbuf length:(NSUInteger)n];
    }
    close(fd);

    return [[NSString alloc] initWithData:accum encoding:NSUTF8StringEncoding] ?: @"";
}

/// Guard → middle → exit style names from a `GETINFO circuit-status` reply (first GENERAL circuit, else first BUILT).
static NSString *IPCParseCircuitPathFromTorReply(NSString *all)
{
    if (all.length == 0) return nil;
    NSArray<NSString *> *lines = [all componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    NSString *chosen = nil;
    for (NSString *line in lines) {
        NSString *t = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([t containsString:@" BUILT "] && [t containsString:@"purpose=GENERAL"]) {
            chosen = t;
        }
    }
    if (!chosen) {
        for (NSString *line in lines) {
            NSString *t = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if ([t containsString:@" BUILT "]) {
                chosen = t;
                break;
            }
        }
    }
    if (!chosen) return nil;

    NSArray<NSString *> *parts = [chosen componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSMutableArray<NSString *> *tokens = [NSMutableArray array];
    for (NSString *p in parts) {
        if (p.length) [tokens addObject:p];
    }

    BOOL pastBuilt = NO;
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    for (NSString *tok in tokens) {
        if (!pastBuilt) {
            if ([tok isEqualToString:@"BUILT"]) pastBuilt = YES;
            continue;
        }
        if ([tok hasPrefix:@"purpose="] || [tok hasPrefix:@"TIME_CREATED="] || [tok hasPrefix:@"REASON="]) {
            break;
        }
        // Later KEY=value metadata without $ (avoid eating unknown pairs)
        NSRange eq = [tok rangeOfString:@"="];
        if (eq.location != NSNotFound && ![tok hasPrefix:@"$"] && [tok rangeOfString:@"~"].location == NSNotFound) {
            break;
        }

        NSString *disp = tok;
        NSRange tilde = [tok rangeOfString:@"~"];
        if (eq.location != NSNotFound && eq.location + 1 < tok.length) {
            disp = [tok substringFromIndex:eq.location + 1];
        } else if (tilde.location != NSNotFound && tilde.location + 1 < tok.length) {
            disp = [tok substringFromIndex:tilde.location + 1];
        } else if ([tok hasPrefix:@"$"] && tok.length > 8) {
            disp = [[[tok substringToIndex:MIN((NSUInteger)13, tok.length)] stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"$"]] stringByAppendingString:@"…"];
        }
        if (disp.length) [names addObject:disp];
    }
    if (names.count == 0) return nil;
    return [names componentsJoinedByString:@" → "];
}

static NSString *IPCTorControlCircuitPathDisplayString(void)
{
    NSMutableString *payload = IPCTorControlPayloadWithAuth();
    [payload appendString:@"GETINFO circuit-status\r\nQUIT\r\n"];
    NSError *err = nil;
    NSString *all = IPCTorControlExchange([payload copy], &err);
    if (all.length == 0) return nil;
    if ([all containsString:@"515 Authentication failed"] || [all containsString:@"514 Authentication required"]) {
        return nil;
    }
    return IPCParseCircuitPathFromTorReply(all);
}

/// Asks Tor for a new circuit without `brew services restart` (no full process stop). Requires ControlPort + cookie in torrc.
static BOOL IPCSendTorNewnym(NSError **outError)
{
    NSMutableString *payload = IPCTorControlPayloadWithAuth();
    [payload appendString:@"SIGNAL NEWNYM\r\nQUIT\r\n"];

    NSString *all = IPCTorControlExchange([payload copy], outError);
    if (!all) return NO;

    if ([all containsString:@"515 Authentication failed"] || [all containsString:@"514 Authentication required"]) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"ipchanger" code:103 userInfo:@{ NSLocalizedDescriptionKey: @"Tor control port rejected AUTHENTICATE (check cookie or ControlPort settings in torrc)." }];
        }
        return NO;
    }
    if ([all containsString:@"553"]) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"ipchanger" code:105 userInfo:@{ NSLocalizedDescriptionKey: @"Tor rate-limits NEWNYM; wait a bit or use a longer interval." }];
        }
        return NO;
    }
    if ([all containsString:@"552"] || [all containsString:@"Unrecognized signal"]) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"ipchanger" code:104 userInfo:@{ NSLocalizedDescriptionKey: @"Tor rejected SIGNAL NEWNYM on this build." }];
        }
        return NO;
    }

    NSUInteger pos = 0;
    NSInteger okCount = 0;
    while (pos < all.length) {
        NSRange r = [all rangeOfString:@"250 OK" options:0 range:NSMakeRange(pos, all.length - pos)];
        if (r.location == NSNotFound) break;
        okCount += 1;
        pos = r.location + r.length;
    }
    if (okCount >= 2) {
        return YES;
    }

    if (outError) {
        *outError = [NSError errorWithDomain:@"ipchanger" code:106 userInfo:@{ NSLocalizedDescriptionKey: all.length ? all : @"No usable reply from Tor control port." }];
    }
    return NO;
}

@interface ipchanger ()
@property (nonatomic, strong) NSStackView *rootStack;
@property (nonatomic, strong) NSTextField *intervalField;
@property (nonatomic, strong) NSTextField *timesField;
@property (nonatomic, strong) NSButton *startButton;
@property (nonatomic, strong) NSButton *stopButton;
@property (nonatomic, strong) NSTextField *ipCaptionLabel;
@property (nonatomic, strong) NSTextField *ipValueField;
@property (nonatomic, strong) NSTextField *countryNameField;
@property (nonatomic, strong) NSTextField *regionNameField;
@property (nonatomic, strong) NSTextField *cityNameField;
@property (nonatomic, strong) NSTextField *ispNameField;
@property (nonatomic, strong) NSTextField *torCircuitField;
@property (nonatomic, strong) NSImageView *flagImageView;
@property (nonatomic, strong) NSTextField *statInternetVal;
@property (nonatomic, strong) NSTextField *statTorVal;
@property (nonatomic, strong) NSTextField *statSOCKSVal;
@property (nonatomic, strong) NSTextField *statRotationVal;
@property (nonatomic, strong) NSTextField *hintField;

@property (atomic, assign) BOOL workerShouldStop;
@property (atomic, assign) BOOL rotationActive;

@property (nonatomic, assign) BOOL didBuildPreferencesUI;
@property (nonatomic, assign) NSInteger uiNilMainViewRetries;

@property (nonatomic, assign) nw_path_monitor_t pathMonitor;
@property (atomic, assign) BOOL internetPathSatisfied;

@property (nonatomic, strong) NSTimer *logPurgeTimer;
@end

static NSFileHandle *IPCNullOutput(void)
{
    static NSFileHandle *handle;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        handle = [NSFileHandle fileHandleForWritingAtPath:@"/dev/null"];
    });
    return handle;
}

static void IPCRunOnBackground(dispatch_block_t block);
static void IPCRunOnMain(dispatch_block_t block);

@implementation ipchanger

#pragma mark - Lifecycle

- (instancetype)initWithBundle:(NSBundle *)bundle
{
    self = [super initWithBundle:bundle];
    if (self) {
        // Defaults only here — do not reset these in mainViewDidLoad: System Settings can reload the
        // main view while a rotation worker is running; resetting workerShouldStop would abort it.
        _workerShouldStop = YES;
        _rotationActive = NO;
    }
    return self;
}

- (NSView *)loadMainView
{
    NSView *root = [super loadMainView];
    [self layoutRootStackInMainView];
    return root;
}

- (void)mainViewDidLoad
{
    [super mainViewDidLoad];
    [self buildPreferencesUIIfNeeded];
    [self layoutRootStackInMainView];
    [self scheduleStatsRefresh];
    [self ipc_startTorLogPurgeTimerIfNeeded];
}

- (void)willSelect
{
    [super willSelect];
    [self buildPreferencesUIIfNeeded];
    [self layoutRootStackInMainView];
    [self scheduleStatsRefresh];
}

- (void)didSelect
{
    [super didSelect];
    [self layoutRootStackInMainView];
    [self scheduleStatsRefresh];
}

/// Builds controls once. Uses Auto Layout from `mainView` so NSStackView / grids get a real width and lay out
/// vertically (frame-only layout + NSBox broke intrinsic heights and caused overlapping views).
- (void)buildPreferencesUIIfNeeded
{
    if (self.didBuildPreferencesUI) return;

    NSView *v = self.mainView;
    if (!v) {
        if (self.uiNilMainViewRetries < 30) {
            self.uiNilMainViewRetries += 1;
            dispatch_async(dispatch_get_main_queue(), ^{ [self buildPreferencesUIIfNeeded]; });
        }
        return;
    }
    self.uiNilMainViewRetries = 0;
    self.didBuildPreferencesUI = YES;

    v.autoresizesSubviews = YES;

    self.intervalField = [[NSTextField alloc] initWithFrame:NSZeroRect];
    self.intervalField.translatesAutoresizingMaskIntoConstraints = NO;

    self.timesField = [[NSTextField alloc] initWithFrame:NSZeroRect];
    self.timesField.placeholderString = @"0";
    self.timesField.translatesAutoresizingMaskIntoConstraints = NO;

    self.startButton = [NSButton buttonWithTitle:@"Start" target:self action:@selector(startRotation:)];
    self.startButton.bezelStyle = NSBezelStyleRounded;
    self.startButton.controlSize = NSControlSizeLarge;
    self.startButton.keyEquivalent = @"\r";

    self.stopButton = [NSButton buttonWithTitle:@"Stop" target:self action:@selector(stopRotation:)];
    self.stopButton.bezelStyle = NSBezelStyleRounded;
    self.stopButton.controlSize = NSControlSizeLarge;
    self.stopButton.enabled = NO;

    NSStackView *buttonRow = [NSStackView stackViewWithViews:@[ self.startButton, self.stopButton ]];
    buttonRow.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    buttonRow.spacing = 14.0;
    buttonRow.alignment = NSLayoutAttributeCenterY;

    NSStackView *rotationInner = [NSStackView stackViewWithViews:@[
        [self intervalRow],
        [self timesRow],
        buttonRow,
    ]];
    rotationInner.orientation = NSUserInterfaceLayoutOrientationVertical;
    rotationInner.alignment = NSLayoutAttributeLeading;
    rotationInner.spacing = 14.0;
    NSView *rotSection = [self ipc_sectionStackTitle:@"Rotation" content:rotationInner];

    self.ipCaptionLabel = [NSTextField labelWithString:@"Exit IP address"];
    self.ipCaptionLabel.font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightSemibold];
    self.ipCaptionLabel.textColor = [NSColor secondaryLabelColor];

    self.ipValueField = [NSTextField labelWithString:@"—"];
    self.ipValueField.font = [NSFont monospacedSystemFontOfSize:17.0 weight:NSFontWeightSemibold];
    self.ipValueField.textColor = [NSColor labelColor];

    self.flagImageView = [[NSImageView alloc] initWithFrame:NSZeroRect];
    self.flagImageView.imageScaling = NSImageScaleProportionallyUpOrDown;
    self.flagImageView.imageAlignment = NSImageAlignCenter;
    self.flagImageView.editable = NO;
    [self ipc_setFlagEmoji:@"🌐"];

    self.countryNameField = [NSTextField labelWithString:@"—"];
    self.countryNameField.font = [NSFont systemFontOfSize:14.0 weight:NSFontWeightMedium];
    self.countryNameField.textColor = [NSColor labelColor];

    NSTextField *countryHdr = [NSTextField labelWithString:@"Country"];
    countryHdr.font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightSemibold];
    countryHdr.textColor = [NSColor secondaryLabelColor];

    self.regionNameField = [NSTextField labelWithString:@"—"];
    self.regionNameField.font = [NSFont systemFontOfSize:14.0 weight:NSFontWeightMedium];
    self.regionNameField.textColor = [NSColor labelColor];
    NSTextField *regionHdr = [NSTextField labelWithString:@"Region"];
    regionHdr.font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightSemibold];
    regionHdr.textColor = [NSColor secondaryLabelColor];

    self.cityNameField = [NSTextField labelWithString:@"—"];
    self.cityNameField.font = [NSFont systemFontOfSize:14.0 weight:NSFontWeightMedium];
    self.cityNameField.textColor = [NSColor labelColor];
    NSTextField *cityHdr = [NSTextField labelWithString:@"City"];
    cityHdr.font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightSemibold];
    cityHdr.textColor = [NSColor secondaryLabelColor];

    self.ispNameField = [NSTextField wrappingLabelWithString:@"—"];
    self.ispNameField.font = [NSFont systemFontOfSize:13.0 weight:NSFontWeightRegular];
    self.ispNameField.textColor = [NSColor labelColor];
    self.ispNameField.preferredMaxLayoutWidth = 380.0;
    NSTextField *ispHdr = [NSTextField labelWithString:@"ISP"];
    ispHdr.font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightSemibold];
    ispHdr.textColor = [NSColor secondaryLabelColor];

    NSStackView *flagTextCol = [NSStackView stackViewWithViews:@[
        countryHdr, self.countryNameField,
        regionHdr, self.regionNameField,
        cityHdr, self.cityNameField,
        ispHdr, self.ispNameField,
    ]];
    flagTextCol.orientation = NSUserInterfaceLayoutOrientationVertical;
    flagTextCol.spacing = 2.0;
    flagTextCol.alignment = NSLayoutAttributeLeading;

    NSStackView *flagRow = [NSStackView stackViewWithViews:@[ self.flagImageView, flagTextCol ]];
    flagRow.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    flagRow.spacing = 18.0;
    flagRow.alignment = NSLayoutAttributeTop;

    [self.flagImageView.widthAnchor constraintEqualToConstant:56.0].active = YES;
    [self.flagImageView.heightAnchor constraintEqualToConstant:40.0].active = YES;

    NSTextField *torCircuitHdr = [NSTextField labelWithString:@"Tor circuit (guard → middle → exit)"];
    torCircuitHdr.font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightSemibold];
    torCircuitHdr.textColor = [NSColor secondaryLabelColor];

    self.torCircuitField = [NSTextField wrappingLabelWithString:@"—"];
    self.torCircuitField.font = [NSFont monospacedSystemFontOfSize:11.0 weight:NSFontWeightRegular];
    self.torCircuitField.textColor = [NSColor labelColor];
    self.torCircuitField.preferredMaxLayoutWidth = 480.0;
    [self.torCircuitField setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationVertical];

    NSStackView *exitInner = [NSStackView stackViewWithViews:@[
        self.ipCaptionLabel,
        self.ipValueField,
        flagRow,
        torCircuitHdr,
        self.torCircuitField,
    ]];
    exitInner.orientation = NSUserInterfaceLayoutOrientationVertical;
    exitInner.alignment = NSLayoutAttributeLeading;
    exitInner.spacing = 10.0;
    NSView *exitSection = [self ipc_sectionStackTitle:@"Exit identity" content:exitInner];

    self.statInternetVal = [self ipc_statValueField];
    self.statTorVal = [self ipc_statValueField];
    self.statSOCKSVal = [self ipc_statValueField];
    self.statRotationVal = [self ipc_statValueField];
    NSGridView *statusGrid = [self ipc_statusGrid];
    NSView *statusSection = [self ipc_sectionStackTitle:@"Connection status" content:statusGrid];

    NSTextField *info = [NSTextField wrappingLabelWithString:@"Traffic must use the Tor SOCKS proxy at 127.0.0.1:9050. Turn off VPNs and iCloud Private Relay to match the exit IP shown here. Tor can be installed with Homebrew when prompted."];
    info.font = [NSFont systemFontOfSize:11.0];
    info.textColor = [NSColor secondaryLabelColor];
    info.preferredMaxLayoutWidth = 480.0;
    [info setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationVertical];

    self.hintField = [NSTextField wrappingLabelWithString:@""];
    self.hintField.font = [NSFont systemFontOfSize:11.0];
    self.hintField.textColor = [NSColor systemOrangeColor];
    self.hintField.preferredMaxLayoutWidth = 480.0;

    NSBox *sep1 = [self ipc_separatorLine];
    NSBox *sep2 = [self ipc_separatorLine];
    NSBox *sep3 = [self ipc_separatorLine];

    NSStackView *form = [NSStackView stackViewWithViews:@[
        rotSection,
        sep1,
        exitSection,
        sep2,
        statusSection,
        sep3,
        info,
        self.hintField,
    ]];
    form.orientation = NSUserInterfaceLayoutOrientationVertical;
    form.alignment = NSLayoutAttributeLeading;
    form.spacing = 22.0;
    form.edgeInsets = NSEdgeInsetsMake(4, 0, 8, 0);
    form.translatesAutoresizingMaskIntoConstraints = NO;
    [form setCustomSpacing:28.0 afterView:rotSection];
    [form setCustomSpacing:28.0 afterView:exitSection];
    [form setCustomSpacing:28.0 afterView:statusSection];

    [v addSubview:form];
    self.rootStack = form;

    static const CGFloat kSide = 26.0;
    static const CGFloat kVert = 22.0;
    [NSLayoutConstraint activateConstraints:@[
        [form.topAnchor constraintEqualToAnchor:v.topAnchor constant:kVert],
        [form.leadingAnchor constraintEqualToAnchor:v.leadingAnchor constant:kSide],
        [form.trailingAnchor constraintEqualToAnchor:v.trailingAnchor constant:-kSide],
    ]];
    NSLayoutConstraint *bottomPin = [form.bottomAnchor constraintLessThanOrEqualToAnchor:v.bottomAnchor constant:-kVert];
    bottomPin.priority = NSLayoutPriorityDefaultHigh;
    bottomPin.active = YES;

    [self startInternetPathMonitorIfNeeded];
}

/// Clears files under canonical Tor *log* folders every few seconds (Homebrew paths). Does not touch Tor data/state dirs.
- (void)ipc_startTorLogPurgeTimerIfNeeded
{
    if (self.logPurgeTimer) {
        return;
    }
    static const NSTimeInterval kIPCLogPurgeIntervalSeconds = 5.0;
    __weak typeof(self) weakSelf = self;
    self.logPurgeTimer = [NSTimer timerWithTimeInterval:kIPCLogPurgeIntervalSeconds repeats:YES block:^(NSTimer *timer) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (self) {
                [self ipc_purgeTorInstallLogFiles];
            }
        });
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.logPurgeTimer forMode:NSRunLoopCommonModes];
}

- (void)ipc_purgeTorInstallLogFiles
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray<NSString *> *dirs = @[
        @"/opt/homebrew/var/log/tor",
        @"/usr/local/var/log/tor",
        [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Logs/Tor"],
    ];
    for (NSString *dir in dirs) {
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) {
            continue;
        }
        NSArray<NSString *> *entries = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *name in entries) {
            if ([name hasPrefix:@"."]) {
                continue;
            }
            NSString *path = [dir stringByAppendingPathComponent:name];
            BOOL isSubdir = NO;
            if (![fm fileExistsAtPath:path isDirectory:&isSubdir]) {
                continue;
            }
            if (isSubdir) {
                continue;
            }
            NSError *err = nil;
            if (![fm removeItemAtPath:path error:&err]) {
                [[NSData data] writeToFile:path options:NSDataWritingAtomic error:nil];
            }
        }
    }
}

- (void)dealloc
{
    [self.logPurgeTimer invalidate];
    self.logPurgeTimer = nil;
    if (_pathMonitor) {
        nw_path_monitor_cancel(_pathMonitor);
        _pathMonitor = NULL;
    }
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)startInternetPathMonitorIfNeeded
{
    if (self.pathMonitor) return;

    nw_path_monitor_t mon = nw_path_monitor_create();
    nw_path_monitor_set_queue(mon, dispatch_get_main_queue());
    __weak typeof(self) weakSelf = self;
    nw_path_monitor_set_update_handler(mon, ^(nw_path_t path) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        self.internetPathSatisfied = (nw_path_get_status(path) == nw_path_status_satisfied);
        [self refreshConnectivityStats];
    });
    nw_path_monitor_start(mon);
    self.pathMonitor = mon;
}

- (void)layoutRootStackInMainView
{
    NSView *v = self.mainView;
    if (!v) return;
    [v setNeedsLayout:YES];
    [v layoutSubtreeIfNeeded];
}

#pragma mark - UI builders

- (NSView *)intervalRow
{
    NSTextField *lab = [NSTextField wrappingLabelWithString:@"Interval in seconds (0 = no wait):"];
    lab.alignment = NSTextAlignmentRight;
    lab.font = [NSFont systemFontOfSize:12.0];
    lab.preferredMaxLayoutWidth = 228.0;
    [lab setContentHuggingPriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];

    self.intervalField.font = [NSFont monospacedSystemFontOfSize:12.0 weight:NSFontWeightRegular];
    self.intervalField.placeholderString = @"0";
    NSStackView *row = [NSStackView stackViewWithViews:@[ lab, self.intervalField ]];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.spacing = 12.0;
    row.alignment = NSLayoutAttributeCenterY;
    row.distribution = NSStackViewDistributionFill;
    [lab.widthAnchor constraintEqualToConstant:232.0].active = YES;
    [self.intervalField.widthAnchor constraintEqualToConstant:88.0].active = YES;
    [self.intervalField setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];
    return row;
}

- (NSView *)timesRow
{
    NSTextField *lab = [NSTextField wrappingLabelWithString:@"Times to change IP (0 = unlimited):"];
    lab.alignment = NSTextAlignmentRight;
    lab.font = [NSFont systemFontOfSize:12.0];
    lab.preferredMaxLayoutWidth = 220.0;
    [lab setContentHuggingPriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];

    NSStackView *row = [NSStackView stackViewWithViews:@[ lab, self.timesField ]];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.spacing = 12.0;
    row.alignment = NSLayoutAttributeCenterY;
    row.distribution = NSStackViewDistributionFill;
    [lab.widthAnchor constraintEqualToConstant:232.0].active = YES;
    [self.timesField.widthAnchor constraintEqualToConstant:88.0].active = YES;
    self.timesField.font = [NSFont monospacedSystemFontOfSize:12.0 weight:NSFontWeightRegular];
    [self.timesField setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];
    return row;
}

- (NSImageView *)ipc_symbolView:(NSString *)symbolName
{
    NSImage *img = [NSImage imageWithSystemSymbolName:symbolName accessibilityDescription:nil];
    NSImageView *iv = [[NSImageView alloc] initWithFrame:NSZeroRect];
    iv.image = img;
    iv.imageScaling = NSImageScaleProportionallyDown;
    if (@available(macOS 11.0, *)) {
        NSImageSymbolConfiguration *cfg = [NSImageSymbolConfiguration configurationWithPointSize:14 weight:NSFontWeightSemibold];
        iv.symbolConfiguration = cfg;
    }
    iv.contentTintColor = [NSColor secondaryLabelColor];
    [iv.widthAnchor constraintEqualToConstant:22.0].active = YES;
    [iv.heightAnchor constraintEqualToConstant:20.0].active = YES;
    return iv;
}

- (NSTextField *)ipc_mutedLabel:(NSString *)text
{
    NSTextField *t = [NSTextField labelWithString:text];
    t.font = [NSFont systemFontOfSize:12.0];
    t.textColor = [NSColor secondaryLabelColor];
    t.lineBreakMode = NSLineBreakByTruncatingTail;
    return t;
}

- (NSTextField *)ipc_statValueField
{
    NSTextField *f = [NSTextField labelWithString:@"—"];
    f.font = [NSFont systemFontOfSize:12.0 weight:NSFontWeightMedium];
    f.textColor = [NSColor labelColor];
    f.alignment = NSTextAlignmentRight;
    f.lineBreakMode = NSLineBreakByTruncatingTail;
    [f setContentCompressionResistancePriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];
    [f.widthAnchor constraintGreaterThanOrEqualToConstant:112.0].active = YES;
    return f;
}

- (NSStackView *)ipc_sectionStackTitle:(NSString *)title content:(NSView *)content
{
    NSTextField *head = [NSTextField labelWithString:title];
    head.font = [NSFont boldSystemFontOfSize:13.0];
    head.textColor = [NSColor labelColor];
    NSStackView *stack = [NSStackView stackViewWithViews:@[ head, content ]];
    stack.orientation = NSUserInterfaceLayoutOrientationVertical;
    stack.spacing = 12.0;
    stack.alignment = NSLayoutAttributeLeading;
    stack.edgeInsets = NSEdgeInsetsMake(2, 0, 4, 0);
    return stack;
}

- (NSBox *)ipc_separatorLine
{
    NSBox *sep = [[NSBox alloc] init];
    sep.boxType = NSBoxSeparator;
    return sep;
}

- (NSGridView *)ipc_statusGrid
{
    NSGridView *g = [NSGridView gridViewWithViews:@[
        @[ [self ipc_symbolView:@"network"], [self ipc_mutedLabel:@"Internet"], self.statInternetVal ],
        @[ [self ipc_symbolView:@"lock.shield"], [self ipc_mutedLabel:@"Tor process"], self.statTorVal ],
        @[ [self ipc_symbolView:@"cable.connector"], [self ipc_mutedLabel:@"SOCKS port 9050"], self.statSOCKSVal ],
        @[ [self ipc_symbolView:@"arrow.triangle.2.circlepath"], [self ipc_mutedLabel:@"IP rotation"], self.statRotationVal ],
    ]];
    g.rowSpacing = 12.0;
    g.columnSpacing = 14.0;
    for (NSInteger row = 0; row < 4; row++) {
        for (NSInteger col = 0; col < 3; col++) {
            NSGridCell *cell = [g cellAtColumnIndex:col rowIndex:row];
            cell.yPlacement = NSGridCellPlacementCenter;
            cell.xPlacement = (col == 2) ? NSGridCellPlacementTrailing : NSGridCellPlacementLeading;
        }
    }
    return g;
}

- (void)ipc_setFlagEmoji:(NSString *)emoji
{
    self.flagImageView.image = [self ipc_imageFromFlagEmoji:emoji];
}

/// Loads a country flag bitmap over Tor (pref panes often render regional-indicator emoji as a blank/globe).
- (void)ipc_setFlagImageFromPNGData:(nullable NSData *)png countryCode:(NSString *)cc
{
    if (png.length > 24) {
        NSImage *img = [[NSImage alloc] initWithData:png];
        if (img && img.size.width > 4.0 && img.size.height > 2.0) {
            img.template = NO;
            self.flagImageView.image = img;
            return;
        }
    }
    [self ipc_setFlagEmoji:[self flagEmojiForISO:cc]];
}

/// Rasterizes emoji for NSImageView. Uses boundingRect + drawWithRect so regional-indicator flags size correctly.
- (NSImage *)ipc_imageFromFlagEmoji:(NSString *)emoji
{
    NSString *s = emoji.length ? emoji : @"🌐";
    NSFont *font = [NSFont fontWithName:@"Apple Color Emoji" size:34.0];
    if (!font) {
        font = [NSFont systemFontOfSize:34.0];
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
    CGFloat tw = MAX(32.0, ceil(NSWidth(br)));
    CGFloat th = MAX(28.0, ceil(NSHeight(br)));
    NSSize sz = NSMakeSize(tw + 12.0, th + 12.0);

    // flipped:NO matches normal AppKit text coordinates; flipped:YES often clips emoji to “empty” / white in small views.
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
    return image;
}

#pragma mark - Actions

- (void)startRotation:(id)sender
{
    self.hintField.stringValue = @"";

    if (self.rotationActive && !self.workerShouldStop) {
        self.hintField.stringValue = @"Rotation is already running. Use Stop to end this session.";
        return;
    }

    NSInteger intervalSeconds = [self.intervalField.stringValue integerValue];
    NSInteger times = [self.timesField.stringValue integerValue];
    if (intervalSeconds < 0) {
        self.hintField.stringValue = @"Interval cannot be negative. Use 0 for no pause between changes.";
        return;
    }
    if (times < 0) {
        self.hintField.stringValue = @"Times cannot be negative. Use 0 for unlimited rotations.";
        return;
    }

    NSString *brew = [self brewPath];
    if (!brew) {
        self.hintField.stringValue = @"Homebrew not found. Install from https://brew.sh/ then reopen System Settings.";
        return;
    }

    self.startButton.enabled = NO;
    self.stopButton.enabled = YES;
    self.workerShouldStop = NO;
    self.rotationActive = YES;

    __weak typeof(self) weakSelf = self;
    IPCRunOnBackground(^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;

        NSError *err = nil;
        if (![self ensureTorInstalled:&err]) {
            IPCRunOnMain(^{
                self.hintField.stringValue = err.localizedDescription ?: @"Could not ensure Tor is installed.";
                self.startButton.enabled = YES;
                self.stopButton.enabled = NO;
                self.rotationActive = NO;
            });
            return;
        }

        if (![self startTorIfNeeded:&err]) {
            IPCRunOnMain(^{
                self.hintField.stringValue = err.localizedDescription ?: @"Could not start Tor.";
                self.startButton.enabled = YES;
                self.stopButton.enabled = NO;
                self.rotationActive = NO;
            });
            return;
        }

        NSInteger remaining = times;
        BOOL unlimited = (times == 0);

        while (!self.workerShouldStop) {
            if (![self rotateTorCircuit:&err]) {
                IPCRunOnMain(^{
                    self.hintField.stringValue = err.localizedDescription ?: @"Tor rotation failed.";
                });
                // Try to bring Tor back without asking the user to press Start again.
                (void)[self startTorIfNeeded:&err];
                if (self.workerShouldStop) break;
                [self interruptibleSleep:2];
            }

            [self interruptibleSleep:1];

            __block NSString *circuitPath = nil;
            __block NSDictionary *snap = nil;
            dispatch_group_t grp = dispatch_group_create();
            dispatch_group_enter(grp);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                circuitPath = IPCTorControlCircuitPathDisplayString();
                dispatch_group_leave(grp);
            });
            dispatch_group_enter(grp);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                snap = [self ipc_captureExitIdentitySnapshot];
                dispatch_group_leave(grp);
            });
            dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

            IPCRunOnMain(^{
                self.torCircuitField.stringValue = circuitPath.length ? circuitPath : @"—";
                [self ipc_applyExitIdentitySnapshot:snap ?: @{}];
                [self refreshConnectivityStats];
            });

            if (!unlimited) {
                remaining -= 1;
                if (remaining <= 0 || self.workerShouldStop) break;
            }

            NSInteger sleepSec = intervalSeconds;
            if (sleepSec > 0) {
                [self interruptibleSleep:sleepSec];
            }
            if (self.workerShouldStop) break;
        }

        IPCRunOnMain(^{
            self.rotationActive = NO;
            self.startButton.enabled = YES;
            self.stopButton.enabled = NO;
            self.workerShouldStop = YES;
            [self refreshConnectivityStats];
        });
    });
}

- (void)stopRotation:(id)sender
{
    // Stop only the rotation worker — leave the Tor service running so the next Start is immediate
    // and matches the behavior users expect from a “stop rotating” control.
    self.workerShouldStop = YES;
    self.rotationActive = NO;
    self.startButton.enabled = YES;
    self.stopButton.enabled = NO;
    [self refreshConnectivityStats];
}

#pragma mark - Tor / shell

- (nullable NSString *)brewPath
{
    NSArray<NSString *> *candidates = @[
        @"/opt/homebrew/bin/brew",
        @"/usr/local/bin/brew",
    ];
    for (NSString *p in candidates) {
        if ([[NSFileManager defaultManager] isExecutableFileAtPath:p]) return p;
    }
    return nil;
}

- (BOOL)ensureTorInstalled:(NSError **)outError
{
    NSString *brew = [self brewPath];
    NSString *check = [NSString stringWithFormat:@"\"%@\" list --formula | /usr/bin/grep -q '^tor$'", brew];
    int code = [self runBashReturnCode:check];
    if (code == 0) return YES;

    NSString *install = [NSString stringWithFormat:@"\"%@\" install tor", brew];
    NSError *err = nil;
    (void)[self runBash:install error:&err];
    if (err || ![self runBashReturnCode:check]) {
        if (outError) *outError = [NSError errorWithDomain:@"ipchanger" code:2 userInfo:@{ NSLocalizedDescriptionKey: @"Installing Tor via brew failed. Run `brew install tor` in Terminal." }];
        return NO;
    }
    return YES;
}

- (BOOL)startTorIfNeeded:(NSError **)outError
{
    if ([self isTorProcessRunning]) return YES;

    NSString *brew = [self brewPath];
    NSString *cmd = [NSString stringWithFormat:@"\"%@\" services start tor", brew];
    NSError *err = nil;
    (void)[self runBash:cmd error:&err];
    [self interruptibleSleep:3];
    if (![self isTorProcessRunning]) {
        if (outError) *outError = [NSError errorWithDomain:@"ipchanger" code:3 userInfo:@{ NSLocalizedDescriptionKey: @"Tor did not start. Try: brew services start tor" }];
        return NO;
    }
    return YES;
}

- (BOOL)rotateTorCircuit:(NSError **)outError
{
    // Prefer Tor control port NEWNYM: new exit IP without stopping the whole daemon (faster, no SOCKS drop).
    NSError *ctrlErr = nil;
    if (IPCSendTorNewnym(&ctrlErr)) {
        return YES;
    }

    NSString *brew = [self brewPath];
    if (!brew) {
        if (outError) *outError = ctrlErr;
        return NO;
    }
    NSString *cmd = [NSString stringWithFormat:@"\"%@\" services restart tor", brew];
    NSError *err = nil;
    (void)[self runBash:cmd error:&err];
    if (err) {
        if (outError) {
            NSString *msg = [NSString stringWithFormat:@"%@ (Falling back after control port: %@)", err.localizedDescription, ctrlErr.localizedDescription ?: @"n/a"];
            *outError = [NSError errorWithDomain:err.domain code:err.code userInfo:@{ NSLocalizedDescriptionKey: msg }];
        }
        return NO;
    }
    return YES;
}

- (BOOL)isTorProcessRunning
{
    NSString *out = [self runBash:@"/usr/bin/pgrep -x tor || true" error:NULL];
    return out.length > 0;
}

- (nullable NSString *)runBash:(NSString *)command error:(NSError **)outError
{
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/bin/bash"];
    task.arguments = @[ @"-lc", command ];

    NSPipe *stdoutPipe = [NSPipe pipe];
    NSPipe *stderrPipe = [NSPipe pipe];
    task.standardOutput = stdoutPipe;
    task.standardError = stderrPipe;

    NSMutableDictionary *env = [[[NSProcessInfo processInfo] environment] mutableCopy];
    env[@"PATH"] = @"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
    task.environment = env;

    @try {
        [task launch];
    } @catch (NSException *ex) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"ipchanger" code:1 userInfo:@{ NSLocalizedDescriptionKey: ex.reason ?: @"task failed" }];
        }
        return nil;
    }

    [task waitUntilExit];

    NSData *so = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
    NSData *se = [[stderrPipe fileHandleForReading] readDataToEndOfFile];
    NSString *sout = [[NSString alloc] initWithData:so encoding:NSUTF8StringEncoding] ?: @"";
    if (task.terminationStatus != 0 && outError) {
        NSString *serr = [[NSString alloc] initWithData:se encoding:NSUTF8StringEncoding] ?: @"";
        *outError = [NSError errorWithDomain:@"ipchanger" code:(int)task.terminationStatus userInfo:@{ NSLocalizedDescriptionKey: serr.length ? serr : sout }];
    }
    return sout;
}

- (int)runBashReturnCode:(NSString *)command
{
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/bin/bash"];
    task.arguments = @[ @"-lc", command ];
    task.standardOutput = IPCNullOutput();
    task.standardError = IPCNullOutput();

    NSMutableDictionary *env = [[[NSProcessInfo processInfo] environment] mutableCopy];
    env[@"PATH"] = @"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
    task.environment = env;

    @try {
        [task launch];
        [task waitUntilExit];
        return (int)task.terminationStatus;
    } @catch (NSException *ex) {
        return -1;
    }
}

#pragma mark - Curl / geo

- (nullable NSString *)curlSOCKS:(NSString *)url UTF8:(BOOL)utf8
{
    NSMutableArray *args = [NSMutableArray arrayWithObjects:
        @"-s", @"--connect-timeout", @"6", @"-m", @"10",
        @"--socks5-hostname", [NSString stringWithFormat:@"%@:%u", kTorSOCKSHost, kTorSOCKSPort],
        url,
        nil];

    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/curl"];
    task.arguments = args;

    NSPipe *stdoutPipe = [NSPipe pipe];
    task.standardOutput = stdoutPipe;
    task.standardError = IPCNullOutput();

    @try {
        [task launch];
    } @catch (NSException *ex) {
        return nil;
    }
    [task waitUntilExit];
    NSData *data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
    if (utf8) {
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
}

- (nullable NSData *)curlSOCKSData:(NSString *)url
{
    NSMutableArray *args = [NSMutableArray arrayWithObjects:
        @"-s", @"--connect-timeout", @"6", @"-m", @"12",
        @"--socks5-hostname", [NSString stringWithFormat:@"%@:%u", kTorSOCKSHost, kTorSOCKSPort],
        url,
        nil];

    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/curl"];
    task.arguments = args;

    NSPipe *stdoutPipe = [NSPipe pipe];
    task.standardOutput = stdoutPipe;
    task.standardError = IPCNullOutput();

    @try {
        [task launch];
    } @catch (NSException *ex) {
        return nil;
    }
    [task waitUntilExit];
    return [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
}

/// Runs on a worker thread: geo JSON + flag PNG (parallel-friendly when called with circuit fetch).
- (NSDictionary *)ipc_captureExitIdentitySnapshot
{
    NSString *json = [self curlSOCKS:@"http://ip-api.com/json/?fields=status,message,query,country,countryCode,city,regionName,isp" UTF8:YES];
    if (json.length) {
        NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if ([dict isKindOfClass:[NSDictionary class]] && [dict[@"status"] isEqualToString:@"success"]) {
            NSString *cc = [dict[@"countryCode"] isKindOfClass:[NSString class]] ? dict[@"countryCode"] : @"";
            NSMutableDictionary *snap = [NSMutableDictionary dictionary];
            snap[@"query"] = dict[@"query"] ?: @"";
            snap[@"country"] = dict[@"country"] ?: @"";
            snap[@"region"] = [dict[@"regionName"] isKindOfClass:[NSString class]] ? dict[@"regionName"] : @"";
            snap[@"city"] = [dict[@"city"] isKindOfClass:[NSString class]] ? dict[@"city"] : @"";
            snap[@"isp"] = [dict[@"isp"] isKindOfClass:[NSString class]] ? dict[@"isp"] : @"";
            snap[@"countryCode"] = cc;
            if (cc.length == 2) {
                NSData *png = [self curlSOCKSData:[NSString stringWithFormat:@"https://flagcdn.com/w80/%@.png", cc.lowercaseString]];
                if (png.length > 24) snap[@"flagPNG"] = png;
            }
            snap[@"ok"] = @YES;
            return snap;
        }
    }

    NSMutableDictionary *snap = [NSMutableDictionary dictionary];
    snap[@"ok"] = @NO;
    NSString *plain = [self curlSOCKS:@"https://checkip.amazonaws.com" UTF8:YES];
    NSString *ip = [[plain stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] copy];
    if (ip.length) snap[@"query"] = ip;
    return snap;
}

- (void)ipc_applyExitIdentitySnapshot:(NSDictionary *)snap
{
    if ([snap[@"ok"] boolValue]) {
        NSString *q = snap[@"query"];
        self.ipValueField.stringValue = ([q isKindOfClass:[NSString class]] && q.length) ? q : @"—";
        NSString *country = snap[@"country"];
        self.countryNameField.stringValue = ([country isKindOfClass:[NSString class]] && country.length) ? country : @"—";
        NSString *region = snap[@"region"];
        self.regionNameField.stringValue = ([region isKindOfClass:[NSString class]] && region.length) ? region : @"—";
        NSString *city = snap[@"city"];
        self.cityNameField.stringValue = ([city isKindOfClass:[NSString class]] && city.length) ? city : @"—";
        NSString *isp = snap[@"isp"];
        self.ispNameField.stringValue = ([isp isKindOfClass:[NSString class]] && isp.length) ? isp : @"—";
        NSString *cc = [snap[@"countryCode"] isKindOfClass:[NSString class]] ? snap[@"countryCode"] : @"";
        NSData *png = [snap[@"flagPNG"] isKindOfClass:[NSData class]] ? snap[@"flagPNG"] : nil;
        [self ipc_setFlagImageFromPNGData:png countryCode:cc];
        return;
    }

    NSString *ip = [snap[@"query"] isKindOfClass:[NSString class]] ? snap[@"query"] : nil;
    if (ip.length) {
        self.ipValueField.stringValue = ip;
        self.countryNameField.stringValue = @"(Geo lookup failed — is Tor SOCKS up?)";
        self.regionNameField.stringValue = @"—";
        self.cityNameField.stringValue = @"—";
        self.ispNameField.stringValue = @"—";
    } else {
        self.ipValueField.stringValue = @"—";
        self.countryNameField.stringValue = @"—";
        self.regionNameField.stringValue = @"—";
        self.cityNameField.stringValue = @"—";
        self.ispNameField.stringValue = @"—";
    }
    [self ipc_setFlagEmoji:@"🌐"];
}

- (void)refreshExitIdentity
{
    __weak typeof(self) weakSelf = self;
    IPCRunOnBackground(^{
        NSDictionary *snap = [weakSelf ipc_captureExitIdentitySnapshot];
        IPCRunOnMain(^{
            [weakSelf ipc_applyExitIdentitySnapshot:snap];
        });
    });
}

- (NSString *)flagEmojiForISO:(NSString *)iso
{
    if (iso.length < 2) return @"🌐";
    NSString *two = [[iso substringToIndex:2] uppercaseString];
    unichar a = [two characterAtIndex:0];
    unichar b = [two characterAtIndex:1];
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return @"🌐";
    return [NSString stringWithFormat:@"%C%C",
        (unichar)(0x1F1E6 + (a - 'A')),
        (unichar)(0x1F1E6 + (b - 'A'))];
}

#pragma mark - Connectivity

- (void)scheduleStatsRefresh
{
    __weak typeof(self) weakSelf = self;
    IPCRunOnBackground(^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        __block NSString *circuitPath = nil;
        __block NSDictionary *snap = nil;
        dispatch_group_t grp = dispatch_group_create();
        dispatch_group_enter(grp);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            circuitPath = IPCTorControlCircuitPathDisplayString();
            dispatch_group_leave(grp);
        });
        dispatch_group_enter(grp);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            snap = [self ipc_captureExitIdentitySnapshot];
            dispatch_group_leave(grp);
        });
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        IPCRunOnMain(^{
            if (!self) return;
            self.torCircuitField.stringValue = circuitPath.length ? circuitPath : @"—";
            [self ipc_applyExitIdentitySnapshot:snap ?: @{}];
            [self refreshConnectivityStats];
        });
    });
}

- (void)refreshConnectivityStats
{
    BOOL inet = [self isInternetReachable];
    BOOL sock = [self isPortOpen:kTorSOCKSHost port:kTorSOCKSPort];
    BOOL tor = [self isTorProcessRunning];

    self.statInternetVal.stringValue = inet ? @"Reachable" : @"Offline";
    self.statInternetVal.textColor = inet ? [NSColor systemGreenColor] : [NSColor systemRedColor];

    self.statTorVal.stringValue = tor ? @"Running" : @"Stopped";
    self.statTorVal.textColor = tor ? [NSColor systemGreenColor] : [NSColor systemOrangeColor];

    self.statSOCKSVal.stringValue = sock ? @"Reachable" : @"Closed";
    self.statSOCKSVal.textColor = sock ? [NSColor systemGreenColor] : [NSColor systemRedColor];

    if (self.rotationActive && !(tor && sock)) {
        self.rotationActive = NO;
        self.workerShouldStop = YES;
        self.startButton.enabled = YES;
        self.stopButton.enabled = NO;
        self.hintField.stringValue = @"Tor or SOCKS went down while rotation was active. Press Start after Tor is running.";
    }

    self.statRotationVal.stringValue = self.rotationActive ? @"Active" : @"Idle";
    self.statRotationVal.textColor = self.rotationActive ? [NSColor controlAccentColor] : [NSColor secondaryLabelColor];

    [self.statInternetVal invalidateIntrinsicContentSize];
    [self.statTorVal invalidateIntrinsicContentSize];
    [self.statSOCKSVal invalidateIntrinsicContentSize];
    [self.statRotationVal invalidateIntrinsicContentSize];
    [self.rootStack invalidateIntrinsicContentSize];
    [self.mainView setNeedsLayout:YES];
    [self layoutRootStackInMainView];
}

- (BOOL)isInternetReachable
{
    return self.internetPathSatisfied;
}

- (BOOL)isPortOpen:(NSString *)host port:(in_port_t)port
{
    NSString *p = [NSString stringWithFormat:@"%u", port];
    NSString *cmd = [NSString stringWithFormat:@"/usr/bin/nc -z -G 1 %@ %@ >/dev/null 2>&1", host, p];
    return [self runBashReturnCode:cmd] == 0;
}

#pragma mark - Utils

static void IPCRunOnBackground(dispatch_block_t block)
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), block);
}

static void IPCRunOnMain(dispatch_block_t block)
{
    dispatch_async(dispatch_get_main_queue(), block);
}

- (void)interruptibleSleep:(NSInteger)seconds
{
    for (NSInteger i = 0; i < seconds && !self.workerShouldStop; i++) {
        usleep(1000000);
    }
}

@end
