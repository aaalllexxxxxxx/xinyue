// xinyue_crack.dylib - Complete 1:1 port of hook_activation.js v6
// Uses ObjC runtime + memory patching only, no Substrate/fishhook dependency
//
// JS equivalent mapping:
//   Interceptor.replace(addr, callback)  -> patch_memory(addr, MOV W0,#1; RET)
//   Interceptor.attach(addr, {onEnter})   -> class_replaceMethod / MSHookFunction
//   Memory.patchCode(addr, writeU32)     -> patch_memory(addr, data)
//   ObjC Interceptor.replace(IMP,...)    -> class_replaceMethod(IMP)
//   ObjC Interceptor.attach(IMP,{onEnter})-> method_exchangeImplementations / custom trampoline

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <dlfcn.h>

extern void sys_icache_invalidate(void *address, size_t size);

#pragma mark - Memory Patch (Memory.patchCode equivalent)

static bool patch_memory(uintptr_t addr, const void *data, size_t size) {
    // ARM64: 16KB pages
    vm_address_t page = addr & ~0x3FFFULL;
    vm_size_t pageSize = 0x4000;

    kern_return_t kr = vm_protect(mach_task_self(), page, pageSize,
                                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        // Try 4KB page
        page = addr & ~0xFFFULL;
        pageSize = 0x1000;
        kr = vm_protect(mach_task_self(), page, pageSize,
                       FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            NSLog(@"[xinyue] vm_protect FAILED at 0x%lx kr=%d", addr, kr);
            return false;
        }
    }

    memcpy((void *)addr, data, size);

    // Restore execute-only
    vm_protect(mach_task_self(), page, pageSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)addr, size);

    // Verify
    if (memcmp((void *)addr, data, size) != 0) {
        NSLog(@"[xinyue] patch verify FAILED at 0x%lx", addr);
        return false;
    }
    return true;
}

#pragma mark - Get image base (Process.findModuleByName equivalent)

static uintptr_t get_image_base(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "xyld")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    // Fallback: find MH_EXECUTE
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->magic == MH_MAGIC_64 && hdr->filetype == MH_EXECUTE) {
            return (uintptr_t)hdr;
        }
    }
    return 0;
}

#pragma mark - findExport (Module.getGlobalExportByName equivalent)

static uintptr_t find_export(const char *symbolName) {
    // Try dlsym with RTLD_DEFAULT
    void *addr = dlsym(RTLD_DEFAULT, symbolName);
    if (addr) return (uintptr_t)addr;

    // Try all loaded images
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (!hdr) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        // Use dlopen + dlsym on each image
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        void *handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
        if (handle) {
            addr = dlsym(handle, symbolName);
            dlclose(handle);
            if (addr) return (uintptr_t)addr;
        }
    }
    return 0;
}

#pragma mark - Patch 1 & 2: Interceptor.replace -> return 1
// ARM64: MOV W0, #1 (0x52800020) ; RET (0xD65F03C0)

static void patch_return_one(uintptr_t addr, const char *label) {
    uint32_t insns[2] = { 0x52800020, 0xD65F03C0 };  // MOV W0, #1; RET
    bool ok = patch_memory(addr, insns, sizeof(insns));
    NSLog(@"[xinyue] [+] %@ REPLACED @ 0x%lx -> returns 1 [%s]", [NSString stringWithUTF8String:label], addr, ok ? "OK" : "FAIL");
}

#pragma mark - Patch 3: LFVerifierExpiryText hook (onLeave: replace nil with 2099 string)
// This needs Interceptor.attach with onLeave. We use a different approach:
// Patch the function to skip the dlsym lookup and use a hardcoded timestamp.
// LFVerifierExpiryText @ 0x100010f00 (base + 0x10f00)
// After function prologue (3 instructions = 12 bytes), at offset 0x0c:
//   Original: ADRP X19, resolved; LDRB W8, [X19,...]; TBZ W8, #0, loc_F28
//   Patch:    MOVZ X8, #0x5BFF; MOVK X8, #0xF489, LSL#16; B loc_F58 (NSDate path)
// This makes X8 = 4102444799 (2099-12-31 23:59:59) and jumps to the
// NSDate dateWithTimeIntervalSince1970: + stringFromDate: path.

static void patch_expiry_text(uintptr_t base) {
    uintptr_t funcAddr = base + 0x10f00;
    uintptr_t patchAddr = funcAddr + 0x0c;  // After 3 prologue instructions
    uintptr_t targetAddr = funcAddr + 0x58; // loc_F58: ADRP X9, classRef_NSDate

    // MOVZ X8, #0x5BFF
    uint32_t movz = 0xD2800000 | (0x5BFF << 5) | 8;
    // MOVK X8, #0xF489, LSL #16
    uint32_t movk = 0xF2A00000 | (0xF489 << 5) | 8;
    // B targetAddr (relative branch)
    int32_t imm = (int32_t)(targetAddr - patchAddr - 8) / 4;
    uint32_t bInsn = 0x14000000 | ((uint32_t)imm & 0x03FFFFFF);

    uint32_t insns[3] = { movz, movk, bInsn };
    bool ok = patch_memory(patchAddr, insns, sizeof(insns));
    NSLog(@"[xinyue] [+] LFVerifierExpiryText PATCH @ 0x%lx -> 2099-12-31 23:59:59 [%s]", patchAddr, ok ? "OK" : "FAIL");
}

#pragma mark - Patch 4: sub_65D614v skip dialog builder (Memory.patchCode)
// Patch at offset+0x08, B instruction to offset+0x88

static void patch_skip_dialog(uintptr_t base, uintptr_t offset, const char *label) {
    uintptr_t patchAddr = base + offset + 0x08;
    uintptr_t targetAddr = base + offset + 0x88;
    int32_t imm = (int32_t)(targetAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)imm & 0x03FFFFFF);
    bool ok = patch_memory(patchAddr, &bInsn, 4);
    NSLog(@"[xinyue] [+] %@ PATCH @ 0x%lx -> B 0x%lx (0x%08x) [%s]",
          [NSString stringWithUTF8String:label], patchAddr, targetAddr, bInsn, ok ? "OK" : "FAIL");
}

#pragma mark - ObjC hooks (Interceptor.attach onEnter / Interceptor.replace)

// We use IMP replacement via class_replaceMethod + method_getImplementation
// This is equivalent to Frida's Interceptor.replace(IMP, NativeCallback)

// --- showLaunchScreen: Interceptor.replace -> no-op ---
static void showLaunchScreen_replacement(id self, SEL _cmd) {
    // no-op (Frida: console.log("showLaunchScreen BLOCKED"))
}

// --- applyRuntimeState: Interceptor.attach onEnter -> force authPassed=YES ---
// We need to call original but with authPassed=1
// Use a trampoline: save original IMP, replace with our version that calls orig with arg4=YES
static IMP g_applyRuntimeState_orig = NULL;

static void applyRuntimeState_hook(id self, SEL _cmd, BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    // Frida: args[5] = ptr(1) -> force authPassed=YES
    if (g_applyRuntimeState_orig) {
        ((void(*)(id, SEL, BOOL, BOOL, BOOL, BOOL))g_applyRuntimeState_orig)
            (self, _cmd, envReady, hudRunning, canExploit, YES);
    }
}

// --- presentViewController: Interceptor.attach onEnter -> block CDKey alerts ---
// We need onEnter with ability to modify args. Use function hook via class_replaceMethod
// and call original after modifying args.
static IMP g_presentVC_orig = NULL;

// Helper: check if title contains CDKey-related keywords
static bool is_cdkey_alert(id presentedVC) {
    Class cls = object_getClass(presentedVC);
    if (!cls || strcmp(class_getName(cls), "UIAlertController") != 0) return false;

    // Get title
    SEL titleSel = sel_registerName("title");
    IMP titleImp = class_getMethodImplementation(cls, titleSel);
    if (!titleImp) return false;
    id titleObj = ((id(*)(id, SEL))titleImp)(presentedVC, titleSel);
    if (!titleObj) return false;

    const char *title = [((NSString *)titleObj) UTF8String];
    if (!title) return false;

    // Check keywords: 心悦, 验证, 激活, 卡密, 失败, 不存在, 输入
    if (strstr(title, "\xe5\xbf\x83\xe6\x82\xa6") || // 心悦
        strstr(title, "\xe9\xaa\x8c\xe8\xaf\x81") || // 验证
        strstr(title, "\xe6\xbf\x80\xe6\xb4\xbb") || // 激活
        strstr(title, "\xe5\x8d\xa1\xe5\xaf\x86") || // 卡密
        strstr(title, "\xe5\xa4\xb1\xe8\xb4\xa5") || // 失败
        strstr(title, "\xe4\xb8\x8d\xe5\xad\x98\xe5\x9c\xa8") || // 不存在
        strstr(title, "\xe8\xbe\x93\xe5\x85\xa5")) {   // 输入
        return true;
    }
    return false;
}

static void presentViewController_hook(id self, SEL _cmd, id presentedVC, BOOL animated, id completion) {
    if (presentedVC && is_cdkey_alert(presentedVC)) {
        NSLog(@"[xinyue] [*] BLOCKING presentation of CDKey alert");
        // Frida: args[4] = ptr(NULL) -> set completion to NULL
        if (g_presentVC_orig) {
            ((void(*)(id, SEL, id, BOOL, id))g_presentVC_orig)
                (self, _cmd, presentedVC, animated, NULL);
        }
    } else {
        // Call original normally
        if (g_presentVC_orig) {
            ((void(*)(id, SEL, id, BOOL, id))g_presentVC_orig)
                (self, _cmd, presentedVC, animated, completion);
        }
    }
}

// --- viewDidAppear: Interceptor.attach onEnter -> auto-dismiss CDKey alerts ---
static IMP g_viewDidAppear_orig = NULL;

static void viewDidAppear_hook(id self, SEL _cmd, BOOL animated) {
    if (g_viewDidAppear_orig) {
        ((void(*)(id, SEL, BOOL))g_viewDidAppear_orig)(self, _cmd, animated);
    }

    // Check if this is a CDKey alert
    Class cls = object_getClass(self);
    if (cls && strcmp(class_getName(cls), "UIAlertController") == 0) {
        if (is_cdkey_alert(self)) {
            NSLog(@"[xinyue] [*] Auto-dismissing CDKey alert");
            // dismissViewControllerAnimated:completion:
            SEL dismissSel = sel_registerName("dismissViewControllerAnimated:completion:");
            [self performSelector:dismissSel withObject:@YES withObject:nil];
        }
    }
}

#pragma mark - ObjC hook installer

static void hook_objc_methods(void) {
    // === ViewController hooks ===
    Class vc = objc_getClass("ViewController");
    if (!vc) {
        NSLog(@"[xinyue] WARNING: ViewController not found, retrying later");
        return;
    }
    NSLog(@"[xinyue] [+] ViewController found");

    // showLaunchScreen -> no-op (Interceptor.replace)
    SEL showSel = sel_registerName("showLaunchScreen");
    Method showMethod = class_getInstanceMethod(vc, showSel);
    if (showMethod) {
        class_replaceMethod(vc, showSel, (IMP)showLaunchScreen_replacement, "v@:");
        NSLog(@"[xinyue] [+] showLaunchScreen replaced no-op");
    }

    // applyRuntimeState -> force authPassed=YES (Interceptor.attach onEnter)
    SEL applySel = sel_registerName("applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:");
    Method applyMethod = class_getInstanceMethod(vc, applySel);
    if (applyMethod) {
        g_applyRuntimeState_orig = method_getImplementation(applyMethod);
        class_replaceMethod(vc, applySel, (IMP)applyRuntimeState_hook, "v@:BBBB");
        NSLog(@"[xinyue] [+] applyRuntimeState hooked (authPassed=YES)");
    }

    // pollActivationThenReveal -> just log (Interceptor.attach)
    // We don't need to modify it, just let it run

    // === presentViewController -> block CDKey alerts ===
    Class uivcClass = objc_getClass("UIViewController");
    if (uivcClass) {
        SEL presentSel = sel_registerName("presentViewController:animated:completion:");
        Method presentMethod = class_getInstanceMethod(uivcClass, presentSel);
        if (presentMethod) {
            g_presentVC_orig = method_getImplementation(presentMethod);
            class_replaceMethod(uivcClass, presentSel, (IMP)presentViewController_hook, "v@:@B@");
            NSLog(@"[xinyue] [+] presentViewController hook installed");
        }

        // viewDidAppear -> auto-dismiss CDKey alerts
        SEL vdaSel = sel_registerName("viewDidAppear:");
        Method vdaMethod = class_getInstanceMethod(uivcClass, vdaSel);
        if (vdaMethod) {
            g_viewDidAppear_orig = method_getImplementation(vdaMethod);
            class_replaceMethod(uivcClass, vdaSel, (IMP)viewDidAppear_hook, "v@:B");
            NSLog(@"[xinyue] [+] viewDidAppear hook for auto-dismiss");
        }
    }
}

#pragma mark - Constructor

__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === Crack dylib v6-port loaded ===");

        uintptr_t base = get_image_base();
        if (base == 0) {
            NSLog(@"[xinyue] ERROR: image base not found, will retry");
            // Retry on next runloop
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                          dispatch_get_main_queue(), ^{
                xinyue_crack_init();
            });
            return;
        }
        NSLog(@"[xinyue] Image base: 0x%lx", base);

        // ========== 1. REPLACE sub_F14144v -> return 1 ==========
        // Try export first, then offset
        uintptr_t addr = find_export("_Z10sub_F14144v");
        if (addr) {
            patch_return_one(addr, "sub_F14144v");
        } else {
            patch_return_one(base + 0x5cacac, "sub_F14144v");
        }

        // ========== 2. REPLACE _LFVerifyNetworkActivation -> return 1 ==========
        addr = find_export("_LFVerifyNetworkActivation");
        if (addr) {
            patch_return_one(addr, "LFVerifyNetworkActivation");
        } else {
            patch_return_one(base + 0x4870, "LFVerifyNetworkActivation");
        }

        // ========== 3. Hook LFVerifierExpiryText -> return 2099 date ==========
        patch_expiry_text(base);

        // ========== 4. SKIP sub_65D614v dialog builder ==========
        patch_skip_dialog(base, 0x58be8, "sub_65D614v (CDKey dialog builder)");

        // ========== 5. ObjC hooks ==========
        hook_objc_methods();

        // Retry ObjC hooks on next runloop (ViewController might not be loaded yet)
        dispatch_async(dispatch_get_main_queue(), ^{
            hook_objc_methods();
        });

        NSLog(@"[xinyue] === All hooks v6 installed ===");
    }
}
