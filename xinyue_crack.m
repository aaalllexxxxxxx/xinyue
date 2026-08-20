// xinyue_crack.dylib - Permanent crack for com.nbxy.app
// No dependency on MobileSubstrate/theos - pure C + ObjC runtime
// Build: see GitHub Actions workflow

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <sys/icache.h>
#import <dlfcn.h>

// ============================================================
// Helper: Get image base address for the main binary
// ============================================================
static uintptr_t get_image_base(void) {
    // First try: find module named "xyld"
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "xyld")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    // Fallback: main executable is always at index 0
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->magic == MH_MAGIC_64 && hdr->filetype == MH_EXECUTE) {
            return (uintptr_t)hdr;
        }
    }
    return 0;
}

// ============================================================
// Helper: Write code patch (make page writable, write, restore, flush icache)
// ============================================================
static bool write_code_patch(uintptr_t addr, const void *data, size_t size) {
    vm_address_t page = addr & ~0x3FFFULL;  // 16KB pages on arm64
    vm_size_t pageSize = 0x4000;

    // Make page writable
    kern_return_t kr = vm_protect(mach_task_self(), page, pageSize,
                                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        // Try 4KB pages (non-arm64e or simulator)
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

    return true;
}

// ============================================================
// Patch 1: Make a function return 1 (int)
// ARM64: MOV W0, #1  (0x52800020) ; RET (0xD65F03C0)
// ============================================================
static void patch_return_one(uintptr_t addr) {
    uint32_t insns[2] = { 0x52800020, 0xD65F03C0 };  // MOV W0, #1; RET
    if (write_code_patch(addr, insns, sizeof(insns))) {
        NSLog(@"[xinyue] Patched @ 0x%lx -> MOV W0,#1; RET", addr);
    } else {
        NSLog(@"[xinyue] FAILED to patch @ 0x%lx", addr);
    }
}

// ============================================================
// Patch 2: Skip dialog builder body, preserve tail-call
// sub_65D614v structure:
//   0x00: STP X29,X30,[SP,#-0x10]!
//   0x04: MOV X29, SP
//   0x08: <dialog building starts here> -> patch B to 0x88
//   ...
//   0x88: LDP X29,X30,[SP],#0x10
//   0x8C: B sub_94E80Dv  (tail-call to ImGui renderer)
// ============================================================
static void patch_skip_dialog(uintptr_t funcAddr) {
    uintptr_t patchAddr = funcAddr + 0x08;
    uintptr_t targetAddr = funcAddr + 0x88;

    // ARM64 B instruction: 0x14000000 | (imm26 & 0x03FFFFFF)
    // imm = (target - source) / 4
    int32_t branchImm = (int32_t)(targetAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)branchImm & 0x03FFFFFFU);

    if (write_code_patch(patchAddr, &bInsn, sizeof(bInsn))) {
        NSLog(@"[xinyue] Dialog builder patched @ 0x%lx -> B 0x%lx (0x%08x)", patchAddr, targetAddr, bInsn);
    } else {
        NSLog(@"[xinyue] FAILED to patch dialog builder @ 0x%lx", patchAddr);
    }
}

// ============================================================
// ObjC method replacements
// ============================================================

// showLaunchScreen -> no-op
static void showLaunchScreen_replacement(id self, SEL _cmd) {
    // Do nothing - block the launch screen / CDKey dialog
}

// applyRuntimeState -> force authPassed=YES
// Store original IMP for calling through
static IMP g_applyRuntimeState_orig = NULL;

// Method signature: -(void)applyRuntimeStateWithEnvironmentReady:(BOOL)envReady
//                                                     hudRunning:(BOOL)hudRunning
//                                             canExploitLocally:(BOOL)canExploit
//                                                     authPassed:(BOOL)authPassed
// ObjC ABI: (id self, SEL _cmd, BOOL, BOOL, BOOL, BOOL)
static void applyRuntimeState_replacement(id self, SEL _cmd, BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    // Call original with authPassed forced to YES
    if (g_applyRuntimeState_orig) {
        ((void(*)(id, SEL, BOOL, BOOL, BOOL, BOOL))g_applyRuntimeState_orig)(self, _cmd, envReady, hudRunning, canExploit, YES);
    }
}

// ============================================================
// Constructor - runs when dylib is loaded
// ============================================================
__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === Crack dylib v1.0 loaded ===");

        uintptr_t base = get_image_base();
        if (base == 0) {
            NSLog(@"[xinyue] ERROR: Could not find image base");
            return;
        }
        NSLog(@"[xinyue] Image base: 0x%lx", base);

        // ---- 1. Patch _LFVerifyNetworkActivation (offset 0x4870) ----
        // Make it return 1 (success)
        patch_return_one(base + 0x4870);

        // ---- 2. Patch sub_F14144v (offset 0x5cacac) ----
        // Make it return 1 (verification success)
        patch_return_one(base + 0x5cacac);

        // ---- 3. Patch sub_65D614v (offset 0x58be8) ----
        // Skip CDKey dialog building, preserve tail-call to sub_94E80Dv
        patch_skip_dialog(base + 0x58be8);

        // ---- 4. Swizzle ViewController ObjC methods ----
        Class viewControllerClass = objc_getClass("ViewController");
        if (viewControllerClass) {
            NSLog(@"[xinyue] ViewController found");

            // 4a. Replace showLaunchScreen with no-op
            SEL showSel = sel_registerName("showLaunchScreen");
            Method showMethod = class_getInstanceMethod(viewControllerClass, showSel);
            if (showMethod) {
                IMP newImp = (IMP)showLaunchScreen_replacement;
                class_replaceMethod(viewControllerClass, showSel, newImp, "v@:");
                NSLog(@"[xinyue] showLaunchScreen replaced with no-op");
            }

            // 4b. Hook applyRuntimeState to force authPassed=YES
            SEL applySel = sel_registerName("applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:");
            Method applyMethod = class_getInstanceMethod(viewControllerClass, applySel);
            if (applyMethod) {
                g_applyRuntimeState_orig = method_getImplementation(applyMethod);
                IMP newImp = (IMP)applyRuntimeState_replacement;
                class_replaceMethod(viewControllerClass, applySel, newImp, "v@:BBBB");
                NSLog(@"[xinyue] applyRuntimeState hooked -> force authPassed=YES");
            }

        } else {
            NSLog(@"[xinyue] WARNING: ViewController class not found");
        }

        NSLog(@"[xinyue] === All patches applied successfully ===");
    }
}
