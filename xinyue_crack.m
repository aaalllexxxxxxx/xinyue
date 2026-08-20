// xinyue_crack.dylib - Permanent crack for com.nbxy.app
// Mirrors Frida v6 exactly: all patches use vm_protect + memcpy (same as Memory.patchCode)
// NO MSHookFunction - pure memory patching only

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <dlfcn.h>

extern void sys_icache_invalidate(void *address, size_t length);

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
// Memory patch - equivalent to Frida's Memory.patchCode
// ============================================================
static bool patch_memory(uintptr_t addr, const void *data, size_t size) {
    // Try 16KB page (arm64) first, then 4KB
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
            NSLog(@"[xinyue] vm_protect WRITE failed: %d at 0x%lx", kr, addr);
            return false;
        }
    }
    
    memcpy((void *)addr, data, size);
    
    vm_protect(mach_task_self(), page, pageSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)addr, size);
    
    // Verify
    if (memcmp((void *)addr, data, size) != 0) {
        NSLog(@"[xinyue] patch verify FAILED at 0x%lx", addr);
        return false;
    }
    return true;
}

// ============================================================
// Patch 1: Make function return 1
// ARM64: MOV W0, #1 (0x52800020) ; RET (0xD65F03C0)
// Same as Frida: Interceptor.replace(addr, new NativeCallback(function(){return 1}, 'int', []))
// ============================================================
static void patch_return_one(uintptr_t addr) {
    uint32_t insns[2] = { 0x52800020, 0xD65F03C0 };  // MOV W0, #1; RET
    bool ok = patch_memory(addr, insns, sizeof(insns));
    NSLog(@"[xinyue] patch_return_one @ 0x%lx -> %s", addr, ok ? "OK" : "FAILED");
}

// ============================================================
// Patch 2: Skip dialog builder, preserve tail-call
// Same as Frida v6: Memory.patchCode writes B instruction at offset+0x08
// jumping to offset+0x88 (LDP X29,X30), then B sub_94E80Dv executes naturally
// ============================================================
static void patch_skip_dialog(uintptr_t funcAddr) {
    uintptr_t patchAddr = funcAddr + 0x08;
    uintptr_t targetAddr = funcAddr + 0x88;
    int32_t imm = (int32_t)(targetAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)imm & 0x03FFFFFFU);
    bool ok = patch_memory(patchAddr, &bInsn, 4);
    NSLog(@"[xinyue] patch_skip_dialog @ 0x%lx -> B 0x%lx (0x%08x) -> %s",
          patchAddr, targetAddr, bInsn, ok ? "OK" : "FAILED");
}

// ============================================================
// ObjC method replacements
// Same as Frida: Interceptor.replace(impl, new NativeCallback(...))
// ============================================================
static IMP g_showLaunchScreen_orig = NULL;
static IMP g_applyRuntimeState_orig = NULL;

static void showLaunchScreen_replacement(id self, SEL _cmd) {
    // no-op - Frida: console.log("[*] showLaunchScreen BLOCKED")
}

static void applyRuntimeState_replacement(id self, SEL _cmd, BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    // Frida: args[5] = ptr(1)  -> force authPassed=YES
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

    // showLaunchScreen -> no-op
    SEL showSel = sel_registerName("showLaunchScreen");
    Method showMethod = class_getInstanceMethod(vc, showSel);
    if (showMethod) {
        g_showLaunchScreen_orig = method_getImplementation(showMethod);
        class_replaceMethod(vc, showSel, (IMP)showLaunchScreen_replacement, "v@:");
        NSLog(@"[xinyue] showLaunchScreen replaced");
    }

    // applyRuntimeState -> force authPassed=YES
    SEL applySel = sel_registerName("applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:");
    Method applyMethod = class_getInstanceMethod(vc, applySel);
    if (applyMethod) {
        g_applyRuntimeState_orig = method_getImplementation(applyMethod);
        class_replaceMethod(vc, applySel, (IMP)applyRuntimeState_replacement, "v@:BBBB");
        NSLog(@"[xinyue] applyRuntimeState hooked");
    }
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === Crack dylib v4.0 loaded ===");

        uintptr_t base = get_image_base();
        if (base == 0) {
            NSLog(@"[xinyue] ERROR: image base not found");
            return;
        }
        NSLog(@"[xinyue] Image base: 0x%lx", base);

        // ---- C function patches (same as Frida v6 Memory.patchCode) ----

        // 1. _LFVerifyNetworkActivation (offset 0x4870) -> MOV W0,#1; RET
        patch_return_one(base + 0x4870);

        // 2. sub_F14144v (offset 0x5cacac) -> MOV W0,#1; RET
        patch_return_one(base + 0x5cacac);

        // 3. sub_65D614v (offset 0x58be8) -> B instruction skip dialog
        //    Same as Frida v6: Memory.patchCode(patchAddr, 4, writeU32(bInsn))
        patch_skip_dialog(base + 0x58be8);

        // ---- ObjC method hooks (same as Frida Interceptor.replace) ----
        hook_objc_methods();

        // Retry on next runloop
        dispatch_async(dispatch_get_main_queue(), ^{
            hook_objc_methods();
        });

        NSLog(@"[xinyue] === All patches applied ===");
    }
}
