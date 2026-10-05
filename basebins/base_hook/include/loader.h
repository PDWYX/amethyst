#ifndef base_hook_loader_h
#define base_hook_loader_h

#include "basebin_common.h"

#define CS_VALID                                0x00000001
#define CS_DEBUGGED                             0x10000000
#define CS_OPS_STATUS                           0x00000000

#define LIBHOOKER_LOADER "/usr/lib/TweakInject.dylib"
#define SUBSTITUTE_LOADER "/usr/lib/substitute-loader.dylib"
#define ELLEKIT_LOADER "/usr/lib/ellekit/libinjector.dylib"
#define SONAR_LOADER "/usr/lib/Sonar/libsonar.dylib"
#define GENERIC_LOADER "/usr/lib/TweakInject.dylib"

/*
 * Daemons that must never be injected: they own the state an app appears to
 * "lose" when tampered with (securityd/keybagd -> keychain, cfprefsd ->
 * preferences, installd/containermanagerd/assertiond/pkd -> containers) or they
 * enforce code signing (amfid) / crash with heap corruption (bluetoothd).
 * Keep this list in sync with basebins/launchd_hook/include/loader.h.
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

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);

void init_loader(void);

#endif /* base_hook_loader_h */
