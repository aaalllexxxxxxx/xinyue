// xinyue_crack.dylib - Permanent crack for com.nbxy.app
// No compile-time dependency on MobileSubstrate
// Uses dlsym to load MSHookFunction at runtime, falls back to vm_protect patching

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <dlfcn.h>

extern void sys_icache_invalidate(void *address, size_t length);

// ============================================================
// MSHookFunction type (loaded via dlsym at runtime)
// ============================================================
typedef void (*MSHookFunction_t)(void *symbol, void *replacement, void **result);
static MSHookFunction_t g_MSHookFunction = NULL;

// ============================================================
// Get image base address
// ============================================================
static uintptr_t get_image_base(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "xyld")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->magic == MH_MAGIC_64 && hdr->filetype == MH_EXECUTE) {
            return (uintptr_t)hdr;
        }
    }
    return 0;
}

// ============================================================
// Fallback: direct memory patch (when MSHookFunction unavailable)
// ============================================================
static bool patch_memory(uintptr_t addr, const void *data, size_t size) {
    vm_address_t page = addr & ~0x3FFFULL;
    vm_size_t pageSize = 0x4000;
    
    kern_return_t kr = vm_protect(mach_task_self(), page, pageSize,
                                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        page = addr & ~0xFFFULL;
        pageSize = 0x1000;
        kr = vm_protect(mach_task_self(), page, pageSize,
                       FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            NSLog(@"[xinyue] vm_protect failed: %d", kr);
            return false;
        }
    }
    
    memcpy((void *)addr, data, size);
    vm_protect(mach_task_self(), page, pageSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)addr, size);
    
    if (memcmp((void *)addr, data, size) != 0) {
        NSLog(@"[xinyue] patch verify FAILED at 0x%lx", addr);
        return false;
    }
    return true;
}

// ============================================================
// Hook functions
// ============================================================

// _LFVerifyNetworkActivation -> return 1
static int (*orig_LFVerifyNetworkActivation)(void) = NULL;
static int hook_LFVerifyNetworkActivation(void) {
    return 1;
}

// sub_F14144v -> return 1
static int (*orig_sub_F14144v)(void) = NULL;
static int hook_sub_F14144v(void) {
    return 1;
}

// sub_65D614v -> skip dialog, call sub_94E80Dv (renderer)
// sub_94E80Dv at offset 0x5cae14
static int (*orig_sub_65D614v)(void) = NULL;
typedef int (*renderer_t)(void);
static renderer_t g_renderer = NULL;

static int hook_sub_65D614v(void) {
    // Skip dialog building, but call the renderer (original tail-call target)
    if (g_renderer) {
        return g_renderer();
    }
    return 1;
}

// ============================================================
// ObjC method replacements
// ============================================================
static IMP g_showLaunchScreen_orig = NULL;
static IMP g_applyRuntimeState_orig = NULL;

static void showLaunchScreen_replacement(id self, SEL _cmd) {
    // no-op
}

static void applyRuntimeState_replacement(id self, SEL _cmd, BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    if (g_applyRuntimeState_orig) {
        ((void(*)(id, SEL, BOOL, BOOL, BOOL, BOOL))g_applyRuntimeState_orig)(self, _cmd, envReady, hudRunning, canExploit, YES);
    }
}

static void hook_objc_methods(void) {
    Class vc = objc_getClass("ViewController");
    if (!vc) {
        NSLog(@"[xinyue] WARNING: ViewController not found");
        return;
    }
    NSLog(@"[xinyue] ViewController found");

    SEL showSel = sel_registerName("showLaunchScreen");
    Method showMethod = class_getInstanceMethod(vc, showSel);
    if (showMethod) {
        g_showLaunchScreen_orig = method_getImplementation(showMethod);
        class_replaceMethod(vc, showSel, (IMP)showLaunchScreen_replacement, "v@:");
        NSLog(@"[xinyue] showLaunchScreen replaced");
    }

    SEL applySel = sel_registerName("applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:");
    Method applyMethod = class_getInstanceMethod(vc, applySel);
    if (applyMethod) {
        g_applyRuntimeState_orig = method_getImplementation(applyMethod);
        class_replaceMethod(vc, applySel, (IMP)applyRuntimeState_replacement, "v@:BBBB");
        NSLog(@"[xinyue] applyRuntimeState hooked");
    }
}

// ============================================================
// Helper: hook or patch a function
// ============================================================
static void hook_function(const char *name, uintptr_t addr, void *hook, void **orig) {
    if (g_MSHookFunction) {
        // Use MobileSubstrate (preferred - same mechanism as Frida)
        g_MSHookFunction((void *)addr, hook, orig);
        NSLog(@"[xinyue] %s hooked via MSHook @ 0x%lx", name, addr);
    } else {
        // Fallback: direct memory patch with MOV W0,#1; RET
        uint32_t insns[2] = { 0x52800020, 0xD65F03C0 };
        bool ok = patch_memory(addr, insns, sizeof(insns));
        NSLog(@"[xinyue] %s patched via vm_protect @ 0x%lx -> %s", name, addr, ok ? "OK" : "FAILED");
    }
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === Crack dylib v3.0 loaded ===");

        // Load MSHookFunction via dlsym (MobileSubstrate is on jailbroken devices)
        g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
        if (g_MSHookFunction) {
            NSLog(@"[xinyue] MobileSubstrate MSHookFunction loaded");
        } else {
            NSLog(@"[xinyue] MSHookFunction not found, using vm_protect fallback");
        }

        uintptr_t base = get_image_base();
        if (base == 0) {
            NSLog(@"[xinyue] ERROR: image base not found");
            return;
        }
        NSLog(@"[xinyue] Image base: 0x%lx", base);

        // Get renderer address (sub_94E80Dv at offset 0x5cae14)
        g_renderer = (renderer_t)(base + 0x5cae14);

        // 1. _LFVerifyNetworkActivation (0x4870) -> return 1
        hook_function("LFVerifyNetworkActivation", base + 0x4870,
                      (void *)hook_LFVerifyNetworkActivation, (void **)&orig_LFVerifyNetworkActivation);

        // 2. sub_F14144v (0x5cacac) -> return 1
        hook_function("sub_F14144v", base + 0x5cacac,
                      (void *)hook_sub_F14144v, (void **)&orig_sub_F14144v);

        // 3. sub_65D614v (0x58be8) -> skip dialog, call renderer
        // For MSHookFunction: use our hook that calls g_renderer
        // For vm_protect fallback: patch B instruction (same as Frida v6)
        if (g_MSHookFunction) {
            g_MSHookFunction((void *)(base + 0x58be8), (void *)hook_sub_65D614v, (void **)&orig_sub_65D614v);
            NSLog(@"[xinyue] sub_65D614v hooked via MSHook @ 0x%lx", base + 0x58be8);
        } else {
            // Fallback: patch B instruction at offset+0x08 -> jump to offset+0x88
            // This skips dialog build but preserves LDP + B sub_94E80Dv
            uintptr_t patchAddr = base + 0x58be8 + 0x08;
            uintptr_t targetAddr = base + 0x58be8 + 0x88;
            int32_t imm = (int32_t)(targetAddr - patchAddr) / 4;
            uint32_t bInsn = 0x14000000U | ((uint32_t)imm & 0x03FFFFFFU);
            bool ok = patch_memory(patchAddr, &bInsn, 4);
            NSLog(@"[xinyue] sub_65D614v patched @ 0x%lx -> B 0x%lx -> %s", patchAddr, targetAddr, ok ? "OK" : "FAILED");
        }

        // 4. ObjC hooks
        hook_objc_methods();
        dispatch_async(dispatch_get_main_queue(), ^{
            hook_objc_methods();
        });

        NSLog(@"[xinyue] === All hooks installed ===");
    }
}
