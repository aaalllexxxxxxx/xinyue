// xinyue_crack.dylib - Permanent crack for com.nbxy.app
// Uses MobileSubstrate MSHookFunction + ObjC runtime (越狱环境)

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

// MobileSubstrate API
extern "C" void MSHookFunction(void *symbol, void *replacement, void **result);
extern "C" void *MSGetImageByName(const char *name);

// ============================================================
// Get function address by offset from image base
// ============================================================
static void *get_func_addr(uintptr_t offset) {
    // Try to find the "xyld" image via MSGetImageByName
    void *image = MSGetImageByName("xyld");
    if (image) {
        return (void *)((uintptr_t)image + offset);
    }
    
    // Fallback: scan dyld images
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "xyld")) {
            return (void *)((uintptr_t)_dyld_get_image_header(i) + offset);
        }
    }
    
    // Last resort: main executable
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->magic == MH_MAGIC_64 && hdr->filetype == MH_EXECUTE) {
            return (void *)((uintptr_t)hdr + offset);
        }
    }
    return NULL;
}

// ============================================================
// Replacement functions for C functions
// ============================================================

// Replacement for _LFVerifyNetworkActivation - always return 1
static int (*orig_LFVerifyNetworkActivation)(void) = NULL;
static int hook_LFVerifyNetworkActivation(void) {
    return 1;
}

// Replacement for sub_F14144v - always return 1
static int (*orig_sub_F14144v)(void) = NULL;
static int hook_sub_F14144v(void) {
    return 1;
}

// Replacement for sub_65D614v - skip dialog build, call through to renderer
// The original function: builds CDKey dialog, then tail-calls sub_94E80Dv
// We skip the dialog building entirely and just call sub_94E80Dv directly
// sub_94E80Dv is at offset 0x5cae14
static int (*orig_sub_65D614v)(void) = NULL;
static int hook_sub_65D614v(void) {
    // Don't build the dialog at all - just return 1
    // The renderer (sub_94E80Dv) is called separately in the ImGui draw loop
    // via drawInMTKView, so we don't need to call it here
    return 1;
}

// ============================================================
// ObjC method replacements
// ============================================================
static IMP g_showLaunchScreen_orig = NULL;
static IMP g_applyRuntimeState_orig = NULL;

static void showLaunchScreen_replacement(id self, SEL _cmd) {
    // no-op - block launch screen
}

static void applyRuntimeState_replacement(id self, SEL _cmd, BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    if (g_applyRuntimeState_orig) {
        ((void(*)(id, SEL, BOOL, BOOL, BOOL, BOOL))g_applyRuntimeState_orig)(self, _cmd, envReady, hudRunning, canExploit, YES);
    }
}

// ============================================================
// Hook ObjC methods
// ============================================================
static void hook_objc_methods(void) {
    Class viewControllerClass = objc_getClass("ViewController");
    if (!viewControllerClass) {
        NSLog(@"[xinyue] WARNING: ViewController not found");
        return;
    }
    NSLog(@"[xinyue] ViewController found");

    // showLaunchScreen -> no-op
    SEL showSel = sel_registerName("showLaunchScreen");
    Method showMethod = class_getInstanceMethod(viewControllerClass, showSel);
    if (showMethod) {
        g_showLaunchScreen_orig = method_getImplementation(showMethod);
        class_replaceMethod(viewControllerClass, showSel, (IMP)showLaunchScreen_replacement, "v@:");
        NSLog(@"[xinyue] showLaunchScreen replaced");
    }

    // applyRuntimeState -> force authPassed=YES
    SEL applySel = sel_registerName("applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:");
    Method applyMethod = class_getInstanceMethod(viewControllerClass, applySel);
    if (applyMethod) {
        g_applyRuntimeState_orig = method_getImplementation(applyMethod);
        class_replaceMethod(viewControllerClass, applySel, (IMP)applyRuntimeState_replacement, "v@:BBBB");
        NSLog(@"[xinyue] applyRuntimeState hooked");
    }
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === Crack dylib v3.0 loaded ===");

        // ---- 1. Hook C functions via MSHookFunction ----
        // These match exactly what Frida's Interceptor.replace does
        
        // _LFVerifyNetworkActivation (offset 0x4870) -> return 1
        void *verifyAddr = get_func_addr(0x4870);
        if (verifyAddr) {
            MSHookFunction(verifyAddr, (void *)hook_LFVerifyNetworkActivation, (void **)&orig_LFVerifyNetworkActivation);
            NSLog(@"[xinyue] LFVerifyNetworkActivation hooked @ 0x%lx", (uintptr_t)verifyAddr);
        }

        // sub_F14144v (offset 0x5cacac) -> return 1
        void *subAddr = get_func_addr(0x5cacac);
        if (subAddr) {
            MSHookFunction(subAddr, (void *)hook_sub_F14144v, (void **)&orig_sub_F14144v);
            NSLog(@"[xinyue] sub_F14144v hooked @ 0x%lx", (uintptr_t)subAddr);
        }

        // sub_65D614v (offset 0x58be8) -> return 1 (skip dialog, don't call renderer)
        void *dialogAddr = get_func_addr(0x58be8);
        if (dialogAddr) {
            MSHookFunction(dialogAddr, (void *)hook_sub_65D614v, (void **)&orig_sub_65D614v);
            NSLog(@"[xinyue] sub_65D614v hooked @ 0x%lx", (uintptr_t)dialogAddr);
        }

        // ---- 2. ObjC method hooks ----
        hook_objc_methods();

        // Retry on next runloop in case classes aren't loaded yet
        dispatch_async(dispatch_get_main_queue(), ^{
            hook_objc_methods();
        });

        NSLog(@"[xinyue] === All hooks installed ===");
    }
}
