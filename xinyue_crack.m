// xinyue_crack.dylib
//
// 完全复刻 hook_activation.js v6 的逻辑
//
// 与 Frida 的关键区别处理：
// 1. showLaunchScreen → Frida 用 Interceptor.replace 改为 no-op
//    dylib 中也 replace 为 no-op（和 Frida 一致）
//    Frida 能正常工作说明这个 hook 是必要的
// 2. presentViewController → Frida 用 Interceptor.attach（不阻止调用！）
//    只设 completion=NULL，弹窗仍然 present，靠 viewDidAppear dismiss
//    dylib 中也这样做（不 return，调用原方法）
// 3. applyRuntimeState → Frida 用 Interceptor.attach，onEnter 改 args[5]=1
//    dylib 用 swizzle，调用原方法时传 authPassed=YES

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/vm_map.h>
#import <mach/mach_init.h>
#include <libkern/OSCacheControl.h>

#define ARM64_MOV_W0_1  0x52800020U
#define ARM64_RET       0xD65F03C0U

#define OFFSET_SUB_F14144V       0x5cacac
#define OFFSET_LFVERIFY_NET_ACT  0x4870
#define OFFSET_SUB_65D614V      0x58be8

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

// ========== 内存 patch ==========
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
    return true;
}

static bool patch_return_one(uintptr_t base, uintptr_t offset, const char *label) {
    uintptr_t addr = base + offset;
    uint32_t insns[] = { ARM64_MOV_W0_1, ARM64_RET };
    NSLog(@"[xinyue] Patch %s @ 0x%lx", label, addr);
    return patch_code(addr, insns, 2);
}

static bool patch_skip_dialog(uintptr_t base, uintptr_t offset, const char *label) {
    uintptr_t patchAddr = base + offset + 0x08;
    uintptr_t ldpAddr = base + offset + 0x88;
    int32_t branchImm = (int32_t)(ldpAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)branchImm & 0x03FFFFFFU);
    NSLog(@"[xinyue] Patch %s @ 0x%lx → B 0x%lx", label, patchAddr, ldpAddr);
    return patch_code(patchAddr, &bInsn, 1);
}

// ========== 卡密关键词检查 ==========
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

// ========== 原始 IMP ==========
static IMP g_orig_present = NULL;
static IMP g_orig_viewDidAppear = NULL;
static IMP g_orig_applyRuntimeState = NULL;

// showLaunchScreen → 不 hook，让它正常执行
// Frida 在 App 已运行后注入，replace no-op 是为了阻止重启时再次显示
// dylib 在 App 启动时注入，showLaunchScreen 必须正常执行
// 否则启动屏状态机卡住，第一次进入卡在加载页面

// ========== Hook: applyRuntimeState → 强制 authPassed=YES ==========
static void hook_applyRuntimeState(id self, SEL _cmd,
    BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    NSLog(@"[xinyue] applyRuntimeState → authPassed=YES");
    if (g_orig_applyRuntimeState) {
        ((void(*)(id, SEL, BOOL, BOOL, BOOL, BOOL))g_orig_applyRuntimeState)(
            self, _cmd, envReady, hudRunning, canExploit, YES);
    }
}

// ========== Hook: presentViewController → 直接阻止卡密弹窗 ==========
// 优化：直接 return 不 present，弹窗根本不会出现
// 比 Frida 的 "present 后再 dismiss" 更干净，无闪烁
static void hook_presentViewController(id self, SEL _cmd,
    id viewController, BOOL animated, id completion) {

    Class cls = object_getClass(viewController);
    NSString *className = NSStringFromClass(cls);

    if ([className isEqualToString:@"UIAlertController"]) {
        NSString *title = nil;
        @try { title = [viewController valueForKey:@"title"]; } @catch(id e) {}

        if (has_cdkey_keyword(title)) {
            NSLog(@"[xinyue] BLOCKING UIAlertController: %@", title);
            // 直接阻止，不调用原方法
            // 调用 completion 表示已完成（避免 App 等待）
            if (completion) {
                ((void(*)(id))completion)(NULL);
            }
            return;
        }
    }

    // 非卡密弹窗，正常调用
    if (g_orig_present) {
        ((void(*)(id, SEL, id, BOOL, id))g_orig_present)(
            self, _cmd, viewController, animated, completion);
    }
}

// ========== Hook: viewDidAppear → 自动 dismiss 卡密弹窗 ==========
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

// ========== 安全 swizzle ==========
static void safe_swizzle(Class cls, SEL sel, IMP newImp, IMP *origImpPtr) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        NSLog(@"[xinyue] Method not found: %@", NSStringFromSelector(sel));
        return;
    }
    if (origImpPtr) *origImpPtr = method_getImplementation(m);
    method_setImplementation(m, newImp);
    NSLog(@"[xinyue] Swizzled: %@", NSStringFromSelector(sel));
}

// ========== 安装 ObjC hooks ==========
static void install_all_objc_hooks(void) {
    NSLog(@"[xinyue] Installing all ObjC hooks...");

    // ViewController hooks
    Class vcClass = objc_getClass("ViewController");
    if (vcClass) {
        NSLog(@"[xinyue] ViewController found");

        // showLaunchScreen → 不 hook（让它正常执行，避免卡在加载页面）
        // applyRuntimeState → authPassed=YES
        safe_swizzle(vcClass,
                     NSSelectorFromString(@"applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:"),
                     (IMP)hook_applyRuntimeState, &g_orig_applyRuntimeState);
    } else {
        NSLog(@"[xinyue] ViewController not found");
    }

    // UIViewController hooks（全局）
    Class uivcClass = [UIViewController class];

    // presentViewController → 不阻止，只设 completion=NULL（和 Frida 一致）
    safe_swizzle(uivcClass,
                 @selector(presentViewController:animated:completion:),
                 (IMP)hook_presentViewController, &g_orig_present);

    // viewDidAppear → 自动 dismiss
    safe_swizzle(uivcClass,
                 @selector(viewDidAppear:),
                 (IMP)hook_viewDidAppear, &g_orig_viewDidAppear);

    NSLog(@"[xinyue] ObjC hooks installed");
}

// ========== 重试安装 ==========
static void try_install_hooks(int attempt) {
    if (attempt > 30) {
        NSLog(@"[xinyue] Hook install: gave up after 30 attempts");
        return;
    }

    Class vcClass = objc_getClass("ViewController");
    if (vcClass) {
        install_all_objc_hooks();
    } else {
        // 先装 UIViewController hooks（不依赖 ViewController）
        if (attempt == 1) {
            Class uivcClass = [UIViewController class];
            safe_swizzle(uivcClass,
                         @selector(presentViewController:animated:completion:),
                         (IMP)hook_presentViewController, &g_orig_present);
            safe_swizzle(uivcClass,
                         @selector(viewDidAppear:),
                         (IMP)hook_viewDidAppear, &g_orig_viewDidAppear);
        }
        NSLog(@"[xinyue] ViewController not loaded, retry %d...", attempt);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            try_install_hooks(attempt + 1);
        });
    }
}

// ========== 主入口 ==========
__attribute__((constructor))
static void xinyue_crack_init(void) {
    NSLog(@"[xinyue] === crack dylib init ===");

    // C 函数 patch：同步执行
    uintptr_t base = get_main_module_base();
    if (base == 0) {
        NSLog(@"[xinyue] FATAL: cannot find main module base");
    } else {
        NSLog(@"[xinyue] main module base: 0x%lx", base);

        // 全部 3 个 C patch（和 Frida JS v6 完全一致）
        patch_return_one(base, OFFSET_SUB_F14144V, "sub_F14144v");
        patch_return_one(base, OFFSET_LFVERIFY_NET_ACT, "LFVerifyNetworkActivation");
        patch_skip_dialog(base, OFFSET_SUB_65D614V, "sub_65D614v");
    }

    // ObjC hooks
    dispatch_async(dispatch_get_main_queue(), ^{
        try_install_hooks(1);
    });

    NSLog(@"[xinyue] === crack dylib done ===");
}
