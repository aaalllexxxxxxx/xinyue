// xinyue_crack.dylib - Complete ObjC translation of hook_activation.js v6
//
// 完整翻译 JS 脚本的所有 hook 点
// 关键修复：
//   1. C 函数 patch 在 constructor 中同步执行（时机最早）
//   2. ObjC hooks 在 +load 中执行（确保类已注册）
//   3. 优先用 dlsym 获取导出符号，失败再用 base+offset
//   4. patch 后立即验证，日志输出确认结果

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <dlfcn.h>

extern void sys_icache_invalidate(void *address, size_t size);

// ============================================================================
// 内存 patch 工具函数
// ============================================================================

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
            NSLog(@"[xinyue] vm_protect FAILED at 0x%lx kr=%d", (unsigned long)addr, kr);
            return false;
        }
    }

    memcpy((void *)addr, data, size);
    vm_protect(mach_task_self(), page, pageSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)addr, size);

    // Verify
    if (memcmp((void *)addr, data, size) != 0) {
        NSLog(@"[xinyue] patch verify FAILED at 0x%lx", (unsigned long)addr);
        return false;
    }
    return true;
}

// 获取 xyld 模块基址
static uintptr_t get_xyld_base(void) {
    NSLog(@"[xinyue] scanning %d modules for xyld...", (int)_dyld_image_count());
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (name && strstr(name, "xyld")) {
            NSLog(@"[xinyue] found xyld [%d]: %s (hdr=%p)", i, name, hdr);
            return (uintptr_t)hdr;
        }
    }
    // Fallback: 找 MH_EXECUTE
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->magic == MH_MAGIC_64 && hdr->filetype == MH_EXECUTE) {
            const char *name = _dyld_get_image_name(i);
            NSLog(@"[xinyue] found MH_EXECUTE [%d]: %s (hdr=%p)", i, name ? name : "(null)", hdr);
            return (uintptr_t)hdr;
        }
    }
    // 打印所有模块用于调试
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        const struct mach_header *hdr = _dyld_get_image_header(i);
        NSLog(@"[xinyue] mod[%d] type=%d magic=0x%x: %s", i,
              hdr ? hdr->filetype : -1, hdr ? hdr->magic : 0, name ? name : "(null)");
    }
    return 0;
}

// 用 dlsym 获取导出符号地址
static uintptr_t resolve_export(const char *symbol) {
    void *addr = dlsym(RTLD_DEFAULT, symbol);
    if (!addr) {
        // 尝试带下划线前缀
        char buf[256];
        snprintf(buf, sizeof(buf), "_%s", symbol);
        addr = dlsym(RTLD_DEFAULT, buf);
    }
    return (uintptr_t)addr;
}

// ============================================================================
// C 函数 patch (等价于 Frida Interceptor.replace / Memory.patchCode)
// ============================================================================

// Patch: 让函数直接返回 1
// ARM64: MOV W0, #1 (0x52800020) ; RET (0xD65F03C0)
static void patch_return_one(uintptr_t addr, const char *label) {
    uint32_t orig[2];
    memcpy(orig, (void *)addr, 8);
    NSLog(@"[xinyue] %s: before patch orig=%08x %08x", label, orig[0], orig[1]);

    uint32_t insns[2] = { 0x52800020, 0xD65F03C0 };
    bool ok = patch_memory(addr, insns, sizeof(insns));

    // 验证
    uint32_t after[2];
    memcpy(after, (void *)addr, 8);
    NSLog(@"[xinyue] %s @ 0x%lx -> MOV W0,#1; RET [%s] after=%08x %08x",
          label, (unsigned long)addr, ok ? "OK" : "FAIL", after[0], after[1]);
}

// Patch: 跳过弹窗构建，保留 tail-call
static void patch_skip_dialog(uintptr_t base, uintptr_t offset, const char *label) {
    uintptr_t patchAddr = base + offset + 0x08;
    uintptr_t targetAddr = base + offset + 0x88;

    uint32_t orig;
    memcpy(&orig, (void *)patchAddr, 4);

    int32_t imm = (int32_t)(targetAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)imm & 0x03FFFFFFU);
    bool ok = patch_memory(patchAddr, &bInsn, 4);

    uint32_t after;
    memcpy(&after, (void *)patchAddr, 4);
    NSLog(@"[xinyue] %s @ 0x%lx orig=%08x -> B 0x%lx (0x%08x) [%s] after=%08x",
          label, (unsigned long)patchAddr, orig, (unsigned long)targetAddr, bInsn,
          ok ? "OK" : "FAIL", after);
}

// ============================================================================
// C 函数 hook: LFVerifierExpiryText -> 返回假日期字符串
// ============================================================================

static CFStringRef g_fakeExpiry = CFSTR("2099-12-31 23:59:59");

static id __attribute__((noinline)) expiry_text_replacement(void) {
    NSLog(@"[xinyue] LFVerifierExpiryText called -> returning fake date");
    return (__bridge id)g_fakeExpiry;
}

static void patch_expiry_text(uintptr_t funcAddr, const char *label) {
    uint32_t orig[4];
    memcpy(orig, (void *)funcAddr, 16);

    uintptr_t target = (uintptr_t)expiry_text_replacement;
    int64_t diff = (int64_t)target - (int64_t)funcAddr;

    NSLog(@"[xinyue] %s: func=0x%lx target=0x%lx diff=0x%llx", label,
          (unsigned long)funcAddr, (unsigned long)target, diff);

    // B 指令范围: ±128MB
    if (diff > 0x7FFFFFFLL || diff < -0x8000000LL) {
        NSLog(@"[xinyue] %s: out of B range, falling back to return-nil", label);
        // 返回 nil 让 JS 的 onLeave 逻辑生效（JS 在 retval.isNull() 时替换）
        // 但这里没有 JS，返回 nil 可能让调用方出问题
        // 改为：patch 成 RET nil，让上层走未激活路径
        uint32_t insns[2] = { 0xD2800000, 0xD65F03C0 }; // MOV X0,#0; RET
        bool ok = patch_memory(funcAddr, insns, sizeof(insns));
        NSLog(@"[xinyue] %s @ 0x%lx -> MOV X0,#0; RET [%s]", label, (unsigned long)funcAddr, ok ? "OK" : "FAIL");
        return;
    }

    int32_t imm = (int32_t)(diff / 4);
    uint32_t bInsn = 0x14000000U | ((uint32_t)imm & 0x03FFFFFFU);
    bool ok = patch_memory(funcAddr, &bInsn, 4);

    uint32_t after;
    memcpy(&after, (void *)funcAddr, 4);
    NSLog(@"[xinyue] %s @ 0x%lx orig=%08x -> B 0x%lx (0x%08x) [%s] after=%08x",
          label, (unsigned long)funcAddr, orig[0], (unsigned long)target, bInsn,
          ok ? "OK" : "FAIL", after);
}

// ============================================================================
// ObjC hooks
// ============================================================================

// --- showLaunchScreen -> no-op ---
static void showLaunchScreen_replacement(id self, SEL _cmd) {
    NSLog(@"[xinyue] showLaunchScreen BLOCKED");
}

// --- applyRuntimeState -> 强制 authPassed=YES ---
static void (*applyRuntimeState_original)(id, SEL, BOOL, BOOL, BOOL, BOOL) = NULL;
static void applyRuntimeState_hook(id self, SEL _cmd, BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    NSLog(@"[xinyue] applyRuntimeState -> authPassed forced YES (was %d)", authPassed);
    if (applyRuntimeState_original) {
        applyRuntimeState_original(self, _cmd, envReady, hudRunning, canExploit, YES);
    }
}

// --- presentViewController -> 拦截卡密弹窗 ---
static void (*presentVC_original)(id, SEL, id, BOOL, id) = NULL;
static void presentVC_hook(id self, SEL _cmd, id presentedVC, BOOL animated, id completion) {
    Class presentedClass = object_getClass(presentedVC);
    Class alertClass = objc_getClass("UIAlertController");
    if (presentedClass == alertClass) {
        NSString *title = @"";
        @try { title = [(UIViewController *)presentedVC title] ?: @""; } @catch(id e) {}

        BOOL shouldBlock = NO;
        NSArray *keywords = @[@"心悦", @"验证", @"激活", @"卡密", @"失败", @"不存在", @"输入"];
        for (NSString *kw in keywords) {
            if ([title containsString:kw]) { shouldBlock = YES; break; }
        }

        if (shouldBlock) {
            NSLog(@"[xinyue] BLOCKING alert: %@", title);
            presentVC_original(self, _cmd, presentedVC, animated, NULL);
            return;
        }
        NSLog(@"[xinyue] alert pass-through: %@", title);
    }

    presentVC_original(self, _cmd, presentedVC, animated, completion);
}

// --- viewDidAppear -> 自动关闭卡密弹窗 ---
static void (*viewDidAppear_original)(id, SEL, BOOL) = NULL;
static void viewDidAppear_hook(id self, SEL _cmd, BOOL animated) {
    viewDidAppear_original(self, _cmd, animated);

    Class selfClass = object_getClass(self);
    Class alertClass = objc_getClass("UIAlertController");
    if (selfClass == alertClass) {
        NSString *title = @"";
        @try { title = [(UIViewController *)self title] ?: @""; } @catch(id e) {}

        BOOL shouldDismiss = NO;
        NSArray *keywords = @[@"心悦", @"验证", @"激活", @"卡密", @"失败", @"不存在", @"输入"];
        for (NSString *kw in keywords) {
            if ([title containsString:kw]) { shouldDismiss = YES; break; }
        }

        if (shouldDismiss) {
            NSLog(@"[xinyue] Auto-dismissing alert: %@", title);
            dispatch_async(dispatch_get_main_queue(), ^{
                [(UIViewController *)self dismissViewControllerAnimated:YES completion:NULL];
            });
        }
    }
}

// ============================================================================
// 安装 ObjC hooks（在 +load 中调用，确保所有类已注册）
// ============================================================================

static void install_objc_hooks(void) {
    NSLog(@"[xinyue] === installing ObjC hooks ===");

    Class vcClass = objc_getClass("ViewController");
    if (vcClass) {
        NSLog(@"[xinyue] ViewController found: %p", vcClass);

        // showLaunchScreen -> no-op
        Method showMethod = class_getInstanceMethod(vcClass, NSSelectorFromString(@"showLaunchScreen"));
        if (showMethod) {
            method_setImplementation(showMethod, (IMP)showLaunchScreen_replacement);
            NSLog(@"[xinyue] showLaunchScreen -> no-op OK");
        } else {
            NSLog(@"[xinyue] showLaunchScreen method not found");
        }

        // applyRuntimeState -> force authPassed=YES
        Method applyMethod = class_getInstanceMethod(vcClass,
            NSSelectorFromString(@"applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:"));
        if (applyMethod) {
            IMP origImpl = method_getImplementation(applyMethod);
            applyRuntimeState_original = (void (*)(id, SEL, BOOL, BOOL, BOOL, BOOL))origImpl;
            method_setImplementation(applyMethod, (IMP)applyRuntimeState_hook);
            NSLog(@"[xinyue] applyRuntimeState -> force authPassed=YES OK");
        } else {
            NSLog(@"[xinyue] applyRuntimeState method not found");
        }
    } else {
        NSLog(@"[xinyue] WARNING: ViewController class not found!");
    }

    // UIViewController hooks
    Class uiVCClass = objc_getClass("UIViewController");
    if (uiVCClass) {
        Method presentMethod = class_getInstanceMethod(uiVCClass,
            NSSelectorFromString(@"presentViewController:animated:completion:"));
        if (presentMethod) {
            IMP origImpl = method_getImplementation(presentMethod);
            presentVC_original = (void (*)(id, SEL, id, BOOL, id))origImpl;
            method_setImplementation(presentMethod, (IMP)presentVC_hook);
            NSLog(@"[xinyue] presentViewController hook OK");
        }

        Method viewDidMethod = class_getInstanceMethod(uiVCClass,
            NSSelectorFromString(@"viewDidAppear:"));
        if (viewDidMethod) {
            IMP origImpl = method_getImplementation(viewDidMethod);
            viewDidAppear_original = (void (*)(id, SEL, BOOL))origImpl;
            method_setImplementation(viewDidMethod, (IMP)viewDidAppear_hook);
            NSLog(@"[xinyue] viewDidAppear hook OK");
        }
    }

    NSLog(@"[xinyue] === ObjC hooks done ===");
}

// ============================================================================
// C 函数 patch（在 constructor 中执行）
// ============================================================================

static void apply_c_patches(void) {
    NSLog(@"[xinyue] === applying C function patches ===");

    uintptr_t base = get_xyld_base();
    if (base == 0) {
        NSLog(@"[xinyue] FATAL: xyld base not found! Cannot patch.");
        return;
    }
    NSLog(@"[xinyue] xyld base = 0x%lx", (unsigned long)base);

    // 1. _LFVerifyNetworkActivation -> return 1
    // 先尝试 dlsym，失败用 base+0x4870
    uintptr_t addr = resolve_export("LFVerifyNetworkActivation");
    if (addr) {
        NSLog(@"[xinyue] LFVerifyNetworkActivation via dlsym = 0x%lx", (unsigned long)addr);
    } else {
        addr = base + 0x4870;
        NSLog(@"[xinyue] LFVerifyNetworkActivation via offset = 0x%lx", (unsigned long)addr);
    }
    patch_return_one(addr, "LFVerifyNetworkActivation");

    // 2. sub_F14144v -> return 1
    addr = resolve_export("_Z10sub_F14144v");
    if (addr) {
        NSLog(@"[xinyue] sub_F14144v via dlsym = 0x%lx", (unsigned long)addr);
    } else {
        addr = base + 0x5cacac;
        NSLog(@"[xinyue] sub_F14144v via offset = 0x%lx", (unsigned long)addr);
    }
    patch_return_one(addr, "sub_F14144v");

    // 3. LFVerifierExpiryText -> 返回假日期
    addr = resolve_export("_ZL20LFVerifierExpiryTextv");
    if (addr) {
        NSLog(@"[xinyue] LFVerifierExpiryText via dlsym = 0x%lx", (unsigned long)addr);
    } else {
        addr = base + 0x10f00;
        NSLog(@"[xinyue] LFVerifierExpiryText via offset = 0x%lx", (unsigned long)addr);
    }
    patch_expiry_text(addr, "LFVerifierExpiryText");

    // 4. sub_65D614v -> 跳过弹窗构建
    patch_skip_dialog(base, 0x58be8, "sub_65D614v");

    NSLog(@"[xinyue] === C patches done ===");
}

// ============================================================================
// Constructor: C 函数 patch（时机最早，在 main() 之前）
// ============================================================================
__attribute__((constructor))
static void xinyue_crack_ctor(void) {
    NSLog(@"[xinyue] === dylib constructor executed ===");
    apply_c_patches();
}

// ============================================================================
// +load: ObjC hooks（时机比 constructor 晚，但确保所有类已注册）
// ============================================================================
@interface XinyueCrackLoader : NSObject
@end
@implementation XinyueCrackLoader
+ (void)load {
    NSLog(@"[xinyue] === XinyueCrackLoader +load ===");
    // ObjC 类在这个时机已经全部注册完成
    // 用 dispatch_async 到 main queue 确保 +load 全部执行完毕
    dispatch_async(dispatch_get_main_queue(), ^{
        install_objc_hooks();
    });
}
@end
