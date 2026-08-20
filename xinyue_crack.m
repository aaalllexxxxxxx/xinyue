// xinyue_crack.dylib - Permanent crack for com.nbxy.app
// Pure C + ObjC runtime, no MobileSubstrate dependency

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <dlfcn.h>

// extern declaration - header path varies across SDKs
extern void sys_icache_invalidate(void *address, size_t length);

// ============================================================
// Get image base address for the main binary
// ============================================================
static uintptr_t get_image_base(void) {
    // Try to find module named "xyld" first
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "xyld")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    // Fallback: main executable (MH_EXECUTE)
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->magic == MH_MAGIC_64 && hdr->filetype == MH_EXECUTE) {
            return (uintptr_t)hdr;
        }
    }
    return 0;
}

// ============================================================
// Write code patch using vm_protect + memcpy + icache flush
// Returns true if patch verified successfully (readback matches)
// ============================================================
static bool write_code_patch(uintptr_t addr, const void *data, size_t size) {
    // Try 16KB pages first (arm64), then 4KB
    vm_address_t page;
    vm_size_t pageSize;
    
    // Try 16KB page alignment
    page = addr & ~0x3FFFULL;
    pageSize = 0x4000;
    
    kern_return_t kr = vm_protect(mach_task_self(), page, pageSize,
                                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        // Try 4KB page alignment
        page = addr & ~0xFFFULL;
        pageSize = 0x1000;
        kr = vm_protect(mach_task_self(), page, pageSize,
                       FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            NSLog(@"[xinyue] vm_protect WRITE failed: %d at 0x%lx", kr, addr);
            return false;
        }
    }

    // Write the patch
    memcpy((void *)addr, data, size);

    // Restore to read+execute only
    vm_protect(mach_task_self(), page, pageSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    // Flush instruction cache
    sys_icache_invalidate((void *)addr, size);

    // Verify patch by reading back
    if (memcmp((void *)addr, data, size) != 0) {
        NSLog(@"[xinyue] Patch verify FAILED at 0x%lx", addr);
        return false;
    }
    
    return true;
}

// ============================================================
// Patch 1: Make function return 1
// ARM64: MOV W0, #1 (0x52800020) ; RET (0xD65F03C0)
// ============================================================
static void patch_return_one(uintptr_t addr) {
    uint32_t insns[2] = { 0x52800020, 0xD65F03C0 };
    bool ok = write_code_patch(addr, insns, sizeof(insns));
    NSLog(@"[xinyue] patch_return_one @ 0x%lx -> %s", addr, ok ? "OK" : "FAILED");
}

// ============================================================
// Patch 2: Skip dialog builder, preserve tail-call
// Patch B instruction at offset+0x08 to jump to offset+0x88
// ============================================================
static void patch_skip_dialog(uintptr_t funcAddr) {
    uintptr_t patchAddr = funcAddr + 0x08;
    uintptr_t targetAddr = funcAddr + 0x88;
    int32_t branchImm = (int32_t)(targetAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)branchImm & 0x03FFFFFFU);
    bool ok = write_code_patch(patchAddr, &bInsn, sizeof(bInsn));
    NSLog(@"[xinyue] patch_skip_dialog @ 0x%lx -> B 0x%lx (0x%08x) -> %s", 
          patchAddr, targetAddr, bInsn, ok ? "OK" : "FAILED");
}

// ============================================================
// ObjC method replacements
// ============================================================
static IMP g_showLaunchScreen_orig = NULL;
static IMP g_applyRuntimeState_orig = NULL;

static void showLaunchScreen_replacement(id self, SEL _cmd) {
    // no-op - block launch screen / CDKey dialog
}

static void applyRuntimeState_replacement(id self, SEL _cmd, BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    if (g_applyRuntimeState_orig) {
        ((void(*)(id, SEL, BOOL, BOOL, BOOL, BOOL))g_applyRuntimeState_orig)(self, _cmd, envReady, hudRunning, canExploit, YES);
    }
}

// ============================================================
// ObjC hooks - done in a dispatch block to ensure classes are loaded
// ============================================================
static void hook_objc_methods(void) {
    Class viewControllerClass = objc_getClass("ViewController");
    if (!viewControllerClass) {
        NSLog(@"[xinyue] WARNING: ViewController class not found");
        return;
    }
    NSLog(@"[xinyue] ViewController found");

    // Replace showLaunchScreen with no-op
    SEL showSel = sel_registerName("showLaunchScreen");
    Method showMethod = class_getInstanceMethod(viewControllerClass, showSel);
    if (showMethod) {
        g_showLaunchScreen_orig = method_getImplementation(showMethod);
        class_replaceMethod(viewControllerClass, showSel, (IMP)showLaunchScreen_replacement, "v@:");
        NSLog(@"[xinyue] showLaunchScreen replaced with no-op");
    }

    // Hook applyRuntimeState to force authPassed=YES
    SEL applySel = sel_registerName("applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:");
    Method applyMethod = class_getInstanceMethod(viewControllerClass, applySel);
    if (applyMethod) {
        g_applyRuntimeState_orig = method_getImplementation(applyMethod);
        class_replaceMethod(viewControllerClass, applySel, (IMP)applyRuntimeState_replacement, "v@:BBBB");
        NSLog(@"[xinyue] applyRuntimeState hooked -> force authPassed=YES");
    }
}

// ============================================================
// Constructor - runs when dylib is loaded
// ============================================================
__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === Crack dylib v2.0 loaded ===");

        // ---- Patch C functions immediately (binary code is already mapped) ----
        uintptr_t base = get_image_base();
        if (base == 0) {
            NSLog(@"[xinyue] ERROR: Could not find image base");
            return;
        }
        NSLog(@"[xinyue] Image base: 0x%lx", base);

        // 1. Patch _LFVerifyNetworkActivation (offset 0x4870)
        patch_return_one(base + 0x4870);

        // 2. Patch sub_F14144v (offset 0x5cacac)
        patch_return_one(base + 0x5cacac);

        // 3. Patch sub_65D614v (offset 0x58be8) - skip dialog builder
        patch_skip_dialog(base + 0x58be8);

        // ---- ObjC hooks - defer to next runloop to ensure classes are registered ----
        // Try immediately first
        hook_objc_methods();

        // Also schedule a retry on next runloop in case classes aren't loaded yet
        dispatch_async(dispatch_get_main_queue(), ^{
            hook_objc_methods();
        });

        NSLog(@"[xinyue] === All patches applied ===");
    }
}
