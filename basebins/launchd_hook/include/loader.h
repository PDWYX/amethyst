#ifndef launchd_hook_loader_h
#define launchd_hook_loader_h

#include "info.h"
#include "codesign.h"

/*
 * Daemons that must never be injected. Besides the restore/keybag daemons this
 * covers the processes that own the state an app appears to "lose" when they
 * are tampered with, and the ones that enforce code signing:
 *   - securityd / keybagd: keychain access (apps asking for a new login)
 *   - cfprefsd: preferences (apps behaving like a first launch even though
 *     their container data is still on disk)
 *   - installd / containermanagerd / assertiond / pkd: app installation and
 *     container registration
 *   - amfid: code signature enforcement (re-signing/installing crashes)
 *   - bluetoothd: crashes with heap corruption when base_hook is loaded
 * Injecting base_hook rewrites the target's credentials, platform flags and
 * code signing flags, which breaks all of the above, so skip them entirely.
 */
static const char *path_block_list[] = {
    "/usr/libexec/keybagd",
    "/usr/libexec/FinishRestoreFromBackup",
    "/usr/libexec/sysstatuscheck",
    "/usr/libexec/usermanagerd",
    "/usr/libexec/init_featureflags",
    "/usr/libexec/FinishRestoreFromBackup",
    "/usr/libexec/adprivacyd",
    "/usr/libexec/amfid",
    "/usr/libexec/assertiond",
    "/usr/libexec/containermanagerd",
    "/usr/libexec/installd",
    "/usr/libexec/pkd",
    "/usr/libexec/securityd",
    "/usr/libexec/cfprefsd",
    "/usr/sbin/cfprefsd",
    "/usr/sbin/securityd",
    "/usr/sbin/bluetoothd",
    NULL
};

static const char *xpc_block_list[] = {
    "com.apple.syslogd",
    "com.apple.logd",
    "com.apple.aslmanager",
    "com.apple.MobileInternetSharing", 
    "com.apple.mobile.keybagd",
    "com.apple.notifyd",
    "com.apple.ReportMemoryException",
    "com.apple.GSSCred",
    "com.apple.UIKit.ShareUI",
    "com.apple.MTLCompilerService",
    "com.apple.cfprefsd",
    "com.apple.securityd",
    "com.apple.MobileFileIntegrity",
    "com.apple.mobile.installd",
    "com.apple.containermanagerd",
    "com.apple.assertiond",
    "com.apple.pkd",
    "com.apple.bluetoothd",
    NULL
};

static const char *jetsam_list[] = {
    "CommCenter",
    "backboardd",
    "SpringBoard",
    "locationd",
    "mediaserverd",
    "com.apple.siri.embeddedspeech",
    NULL
};

typedef int (*orig_spawn_t)(pid_t *, const char *, posix_spawn_file_actions_t *, posix_spawnattr_t *, char **, char **);

int process_binary(const char *path);
int init_loader(void);

#endif /* launchd_hook_loader_h */
