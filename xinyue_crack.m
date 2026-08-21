// xinyue_crack.dylib
//
// 纯 ObjC 实现 hook_activation.js v6 的全部逻辑，不依赖 Frida
// 注入后永久绕过心悦漏打卡密验证
//
// 原理：
// 1. C 函数内存 patch（vm_protect + memcpy + sys_icache_invalidate）
//    - sub_F14144v @ 0x5cacac → MOV W0,#1; RET（验证子函数始终返回1）
//    - _LFVerifyNetworkActivation @ 0x4870 → MOV W0,#1; RET（网络验证始终返回1）
//    - sub_65D614v @ 0x58be8+0x08 → B 跳过弹窗构建，保留 tail-call
// 2. ObjC method swizzle（method_setImplementation 保存原始 IMP）
//    - ViewController.showLaunchScreen → no-op（阻止启动屏）
//    - ViewController.applyRuntimeState... → 强制 authPassed=1
//    - UIViewController.presentViewController → 拦截卡密弹窗
//    - UIViewController.viewDidAppear → 自动 dismiss 卡密弹窗
//
// 关键：所有 hook 延迟到 dispatch_async(main_queue) 执行，
// 确保所有模块和类已加载完成，避免 constructor 中过早 hook 导致闪退

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/vm_map.h>
#import <mach/mach_init.h>
#include <libkern/OSCacheControl.h>

// ========== ARM64 指令编码 ==========
#define ARM64_MOV_W0_1  0x52800020U
#define ARM64_RET       0xD65F03C0U

// Patch 点偏移（来自 hook_activation.js v6）
#define OFFSET_SUB_F14144V       0x5cacac
#define OFFSET_LFVERIFY_NET_ACT  0x4870
#define OFFSET_SUB_65D614V       0x58be8

// ========== 获取主模块基址 ==========
static uintptr_t get_main_module_base(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "/xyld")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && (hdr->filetype == MH_EXECUTE)) {
            return (uintptr_t)hdr;
        }
    }
    return 0;
}

// ========== 内存 patch 工具函数 ==========
static bool patch_code(uintptr_t addr, const uint32_t *insn, size_t count) {
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = addr & ~((uintptr_t)page_size - 1);
    size_t patch_size = count * 4;
    uintptr_t patch_end = addr + patch_size;
    size_t total_size = patch_end - page_start;
    if (total_size < (size_t)page_size) total_size = page_size;

    kern_return_t kr = vm_protect(
        mach_task_self(),
        (vm_address_t)page_start,
        (vm_size_t)total_size,
        false,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
    );
    if (kr != KERN_SUCCESS) {
        NSLog(@"[xinyue] vm_protect RWX FAILED: %d", kr);
        return false;
    }

    memcpy((void *)addr, insn, patch_size);
    sys_icache_invalidate((void *)addr, patch_size);

    kr = vm_protect(
        mach_task_self(),
        (vm_address_t)page_start,
        (vm_size_t)total_size,
        false,
        VM_PROT_READ | VM_PROT_EXECUTE
    );
    if (kr != KERN_SUCCESS) {
        NSLog(@"[xinyue] vm_protect restore RX warning: %d", kr);
    }
    return true;
}

// ========== C 函数 patch ==========
static bool patch_return_one(uintptr_t base, uintptr_t offset, const char *label) {
    uintptr_t addr = base + offset;
    uint32_t insns[] = { ARM64_MOV_W0_1, ARM64_RET };
    NSLog(@"[xinyue] Patch %s @ 0x%lx → MOV W0,#1; RET", label, addr);
    if (!patch_code(addr, insns, 2)) {
        NSLog(@"[xinyue] FAILED to patch %s", label);
        return false;
    }
    NSLog(@"[xinyue] %s patched OK", label);
    return true;
}

static bool patch_skip_dialog(uintptr_t base, uintptr_t offset, const char *label) {
    uintptr_t patchAddr = base + offset + 0x08;
    uintptr_t ldpAddr = base + offset + 0x88;
    int32_t branchImm = (int32_t)(ldpAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)branchImm & 0x03FFFFFFU);

    NSLog(@"[xinyue] Patch %s @ 0x%lx → B 0x%lx", label, patchAddr, ldpAddr);
    if (!patch_code(patchAddr, &bInsn, 1)) {
        NSLog(@"[xinyue] FAILED to patch %s", label);
        return false;
    }
    NSLog(@"[xinyue] %s patched: dialog skipped", label);
    return true;
}

// ========== ObjC hook: 检查卡密关键词 ==========
static bool has_cdkey_keyword(NSString *title) {
    if (!title || title.length == 0) return false;
    static NSArray *keywords = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        keywords = @[@"心悦", @"验证", @"激活", @"卡密",
                     @"失败", @"不存在", @"输入"];
    });
    for (NSString *kw in keywords) {
        if ([title rangeOfString:kw].location != NSNotFound) return true;
    }
    return false;
}

// ========== 保存原始 IMP ==========
static IMP g_orig_present = NULL;
static IMP g_orig_viewDidAppear = NULL;
static IMP g_orig_applyRuntimeState = NULL;

// ========== Hook 函数实现 ==========

// showLaunchScreen → no-op
static void hook_showLaunchScreen(id self, SEL _cmd) {
    NSLog(@"[xinyue] showLaunchScreen BLOCKED");
}

// applyRuntimeState → 强制 authPassed=YES
static void hook_applyRuntimeState(id self, SEL _cmd,
    BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {

    if (g_orig_applyRuntimeState) {
        ((void(*)(id, SEL, BOOL, BOOL, BOOL, BOOL))g_orig_applyRuntimeState)(
            self, _cmd, envReady, hudRunning, canExploit, YES);
    }
    NSLog(@"[xinyue] applyRuntimeState → authPassed forced to YES");
}

// presentViewController → 拦截卡密弹窗
static void hook_presentViewController(id self, SEL _cmd,
    id viewController, BOOL animated, id completion) {

    Class cls = object_getClass(viewController);
    NSString *className = NSStringFromClass(cls);

    if ([className isEqualToString:@"UIAlertController"]) {
        NSString *title = nil;
        @try { title = [viewController valueForKey:@"title"]; } @catch(id e) {}

        if (has_cdkey_keyword(title)) {
            NSLog(@"[xinyue] BLOCKING UIAlertController: %@", title);
            return;
        }
    }

    if (g_orig_present) {
        ((void(*)(id, SEL, id, BOOL, id))g_orig_present)(
            self, _cmd, viewController, animated, completion);
    }
}

// viewDidAppear → 自动 dismiss 卡密弹窗
static void hook_viewDidAppear(id self, SEL _cmd, BOOL animated) {
    if (g_orig_viewDidAppear) {
        ((void(*)(id, SEL, BOOL))g_orig_viewDidAppear)(self, _cmd, animated);
    }

    NSString *className = NSStringFromClass(object_getClass(self));
    if ([className isEqualToString:@"UIAlertController"]) {
        NSString *title = nil;
        @try { title = [self valueForKey:@"title"]; } @catch(id e) {}

        if (has_cdkey_keyword(title)) {
            NSLog(@"[xinyue] Auto-dismissing: %@", title);
            dispatch_async(dispatch_get_main_queue(), ^{
                [self dismissViewControllerAnimated:YES completion:NULL];
            });
        }
    }
}

// ========== 安全 swizzle：保存原始 IMP 后替换 ==========
static void safe_swizzle(Class cls, SEL sel, IMP newImp, IMP *origImpPtr) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        NSLog(@"[xinyue] Method not found: %@", NSStringFromSelector(sel));
        return;
    }
    // 保存原始 IMP
    if (origImpPtr) *origImpPtr = method_getImplementation(m);
    // 替换
    method_setImplementation(m, newImp);
    NSLog(@"[xinyue] Swizzled: %@", NSStringFromSelector(sel));
}

// ========== 安装 ObjC hooks ==========
static void install_objc_hooks(void) {
    NSLog(@"[xinyue] Installing ObjC hooks...");

    // 1. ViewController hooks
    Class vcClass = objc_getClass("ViewController");
    if (vcClass) {
        NSLog(@"[xinyue] ViewController found");

        // showLaunchScreen → no-op
        safe_swizzle(vcClass,
                     NSSelectorFromString(@"showLaunchScreen"),
                     (IMP)hook_showLaunchScreen, NULL);

        // applyRuntimeState → authPassed=YES
        safe_swizzle(vcClass,
                     NSSelectorFromString(@"applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:"),
                     (IMP)hook_applyRuntimeState, &g_orig_applyRuntimeState);
    } else {
        NSLog(@"[xinyue] ViewController not found");
    }

    // 2. UIViewController hooks（全局生效）
    Class uivcClass = [UIViewController class];

    // presentViewController → 拦截卡密弹窗
    safe_swizzle(uivcClass,
                 @selector(presentViewController:animated:completion:),
                 (IMP)hook_presentViewController, &g_orig_present);

    // viewDidAppear → 自动 dismiss
    safe_swizzle(uivcClass,
                 @selector(viewDidAppear:),
                 (IMP)hook_viewDidAppear, &g_orig_viewDidAppear);

    NSLog(@"[xinyue] ObjC hooks installed");
}

// ========== 重试安装 ViewController hooks ==========
static void try_install_vc_hooks(int attempt) {
    if (attempt > 30) {
        NSLog(@"[xinyue] ViewController hook: gave up after 30 attempts");
        // 即使 ViewController 没找到，UIViewController hooks 仍然已安装
        return;
    }

    Class vcClass = objc_getClass("ViewController");
    if (vcClass) {
        install_objc_hooks();
    } else {
        if (attempt == 1) {
            // 第一次先安装 UIViewController 级别的 hooks（不依赖 ViewController 类）
            Class uivcClass = [UIViewController class];
            safe_swizzle(uivcClass,
                         @selector(presentViewController:animated:completion:),
                         (IMP)hook_presentViewController, &g_orig_present);
            safe_swizzle(uivcClass,
                         @selector(viewDidAppear:),
                         (IMP)hook_viewDidAppear, &g_orig_viewDidAppear);
        }
        NSLog(@"[xinyue] ViewController not loaded, retry %d...", attempt);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            try_install_vc_hooks(attempt + 1);
        });
    }
}

// ========== 主入口 ==========
__attribute__((constructor))
static void xinyue_crack_init(void) {
    NSLog(@"[xinyue] === crack dylib init (pure ObjC, no Frida) ===");

    dispatch_async(dispatch_get_main_queue(), ^{

        // ===== C 函数 patch =====
        uintptr_t base = get_main_module_base();
        if (base == 0) {
            NSLog(@"[xinyue] FATAL: cannot find main module base");
        } else {
            NSLog(@"[xinyue] main module base: 0x%lx", base);

            patch_return_one(base, OFFSET_SUB_F14144V, "sub_F14144v");
            patch_return_one(base, OFFSET_LFVERIFY_NET_ACT, "LFVerifyNetworkActivation");
            patch_skip_dialog(base, OFFSET_SUB_65D614V, "sub_65D614v (CDKey dialog)");
        }

        // ===== ObjC hooks =====
        try_install_vc_hooks(1);
    });

    NSLog(@"[xinyue] === crack dylib scheduled ===");
}
