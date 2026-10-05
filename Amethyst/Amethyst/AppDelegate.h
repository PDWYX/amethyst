#import <UIKit/UIKit.h>

typedef enum : NSUInteger {
    Exploit_Hemlock,
    Exploit_Trigon
} AmethystExploitOption;

@interface AmethystConfig : NSObject
@property (nonatomic, strong) NSUserDefaults *defaults;
@property (nonatomic, strong) NSString *trigonCachePath;
@property (nonatomic, assign) CFMutableDictionaryRef trigonCache;
@property (nonatomic, strong) NSString *themeName;
@property (nonatomic, strong) NSString *generator;
// YES only once the user saved a generator explicitly, so the default value is
// not written to the boot nonce on every jailbreak.
@property (nonatomic, assign) bool generatorUserSet;
@property (nonatomic, assign) AmethystExploitOption exploit;
@property (nonatomic, assign) bool lightMode;
@property (nonatomic, assign) bool enableTweaks;
@property (nonatomic, assign) bool restoreRootfs;
@property (nonatomic, assign) bool trigonSupported;
@property (nonatomic, assign) CGFloat buttonCardWidth;
@property (nonatomic, assign) CGFloat popupCardWidth;
@property (nonatomic, assign) CGFloat popupCardHeight;

- (void)loadConfig;
- (void)saveConfig;
- (NSString *)exploitString;
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

extern AmethystConfig *amethyst;
