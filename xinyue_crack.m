// xinyue_crack.dylib - Complete ObjC translation of hook_activation.js v6
//
// 完整翻译 JS 脚本的所有 hook 点：
//   1. C 函数 patch: _LFVerifyNetworkActivation, sub_F14144v -> return 1
//   2. C 函数 patch: sub_65D614v -> B 指令跳过弹窗构建
//   3. C 函数 hook: LFVerifierExpiryText -> 返回 "2099-12-31 23:59:59"
//   4. ObjC hook: ViewController showLaunchScreen -> no-op
//   5. ObjC hook: ViewController applyRuntimeState -> 强制 authPassed=YES
//   6. ObjC hook: UIViewController presentViewController -> 拦截卡密弹窗
//   7. ObjC hook: UIViewController viewDidAppear -> 自动关闭弹窗
//
// 关键：constructor 中直接同步执行所有 patch，不用 dispatch_async
// 因为 constructor 执行时机比 main() 早，这时验证函数还没被调用

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <dispatch/dispatch.h>

extern void sys_icache_invalidate(void *address, size_t size);

// ============================================================================
// 内存 patch 工具函数
// ============================================================================

static bool patch_memory(uintptr_t addr, const void *data, size_t size) {
    // iOS 16K page size
    vm_address_t page = addr & ~0x3FFFULL;
    vm_size_t pageSize = 0x4000;

    kern_return_t kr = vm_protect(mach_task_self(), page, pageSize,
                                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        // Try 4K page
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

    if (memcmp((void *)addr, data, size) != 0) {
        NSLog(@"[xinyue] patch verify FAILED at 0x%lx", (unsigned long)addr);
        return false;
    }
    return true;
}

static uintptr_t get_xyld_base(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "xyld")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    // Fallback: 找主可执行文件
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr && hdr->magic == MH_MAGIC_64 && hdr->filetype == MH_EXECUTE) {
            return (uintptr_t)hdr;
        }
    }
    return 0;
}

// ============================================================================
// C 函数 patch (等价于 Frida Interceptor.replace / Memory.patchCode)
// ============================================================================

// Patch: 让函数直接返回 1
// ARM64: MOV W0, #1 (0x52800020) ; RET (0xD65F03C0)
static void patch_return_one(uintptr_t addr, const char *label) {
    uint32_t orig[2];
    memcpy(orig, (void *)addr, 8);

    uint32_t insns[2] = { 0x52800020, 0xD65F03C0 };
    bool ok = patch_memory(addr, insns, sizeof(insns));
    NSLog(@"[xinyue] %s @ 0x%lx (orig: %08x %08x) -> MOV W0,#1; RET [%s]",
          label, (unsigned long)addr, orig[0], orig[1], ok ? "OK" : "FAIL");
}

// Patch: 跳过弹窗构建，保留 tail-call
// sub_65D614v 结构:
//   0x00: STP X29,X30,[SP,#-0x10]!  (栈帧)
//   0x04: MOV X29, SP
//   0x08..0x84: 弹窗构建调用
//   0x88: LDP X29,X30,[SP],#0x10    (恢复栈帧)
//   0x8C: B sub_94E80Dv              (tail-call 到 ImGui 渲染器)
// 在 offset+0x08 处写 B 指令跳到 offset+0x88
static void patch_skip_dialog(uintptr_t base, uintptr_t offset, const char *label) {
    uintptr_t patchAddr = base + offset + 0x08;
    uintptr_t targetAddr = base + offset + 0x88;

    uint32_t orig;
    memcpy(&orig, (void *)patchAddr, 4);

    int32_t imm = (int32_t)(targetAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)imm & 0x03FFFFFFU);
    bool ok = patch_memory(patchAddr, &bInsn, 4);
    NSLog(@"[xinyue] %s @ 0x%lx (orig: %08x) -> B 0x%lx (0x%08x) [%s]",
          label, (unsigned long)patchAddr, orig, (unsigned long)targetAddr, bInsn, ok ? "OK" : "FAIL");
}

// ============================================================================
// C 函数 hook: LFVerifierExpiryText -> 返回假日期字符串
// 等价于 Frida Interceptor.attach onLeave: retval.replace(fakeStr)
// 实现方式：在函数返回路径上 patch，让它直接返回我们的假字符串
// 但因为 LFVerifierExpiryText 返回的是一个全局缓存的 NSString*，
// 我们用更简单的方法：直接 patch 函数为 MOV X0, #addr; RET
// 不过因为返回的是 Objective-C 对象指针，我们需要返回一个常量字符串
//
// 更好的方案：用 fishhook 或 inline hook 来拦截返回值
// 但最简单可靠的方案：直接 patch 函数让它返回一个固定的 NSString
// 我们在 dylib 中创建一个静态 NSString，然后让函数返回它
// ============================================================================

// 由于 ARM64 的 MOV 指令无法直接加载 64 位地址到 X0，
// 我们需要用 ADRP+ADD 或 LDR 方式。
// 但更简单的方法：patch LFVerifierExpiryText 让它直接调用我们的函数

// 我们的替代函数：返回 "2099-12-31 23:59:59"
// 用 CFString 常量避免 ARC 全局变量问题
static CFStringRef g_fakeExpiry = CFSTR("2099-12-31 23:59:59");
static id __attribute__((noinline)) expiry_text_replacement(void) {
    return (__bridge id)g_fakeExpiry;
}

// Patch LFVerifierExpiryText: 用 B 指令跳转到我们的替代函数
// ARM64 B 指令可以跳转 ±128MB 范围
static void patch_expiry_text(uintptr_t funcAddr, const char *label) {
    // 读原始字节
    uint32_t orig[4];
    memcpy(orig, (void *)funcAddr, 16);

    uintptr_t target = (uintptr_t)expiry_text_replacement;
    int64_t diff = (int64_t)target - (int64_t)funcAddr;

    // 检查是否在 B 指令的跳转范围内 (±128MB)
    if (diff > 0x7FFFFFFLL || diff < -0x8000000LL) {
        // 超出 B 指令范围，用 LDR + BR 方式
        // 这种情况下不能简单 patch，需要更复杂的 trampoline
        // 但实际上 dylib 和主二进制在同一进程空间，距离应该在范围内
        NSLog(@"[xinyue] %s: target out of B range (diff=0x%llx), trying LDR approach", label, diff);

        // 用 ADRP + BR 的方式（但需要可写的 trampoline 区域）
        // 退而求其次：直接 patch 成返回 nil（让调用方走 null 路径）
        // 实际上 JS 脚本就是在 retval.isNull() 时替换，所以返回 nil 也能触发
        // 但我们改为直接返回假字符串更好
        // 尝试用 BL 方式（26 位偏移，±64MB）
        // 如果不行就放弃这个 patch
        NSLog(@"[xinyue] %s: falling back to return-nil patch", label);
        // MOV X0, #0 ; RET = return nil
        uint32_t insns[2] = { 0xD2800000, 0xD65F03C0 }; // MOV X0,#0; RET
        bool ok = patch_memory(funcAddr, insns, sizeof(insns));
        NSLog(@"[xinyue] %s @ 0x%lx -> MOV X0,#0; RET [%s]", label, (unsigned long)funcAddr, ok ? "OK" : "FAIL");
        return;
    }

    // 计算偏移（以指令为单位，即字节数 / 4）
    int32_t imm = (int32_t)(diff / 4);
    uint32_t bInsn = 0x14000000U | ((uint32_t)imm & 0x03FFFFFFU);
    bool ok = patch_memory(funcAddr, &bInsn, 4);
    NSLog(@"[xinyue] %s @ 0x%lx (orig: %08x) -> B 0x%lx (0x%08x) [%s]",
          label, (unsigned long)funcAddr, orig[0], (unsigned long)target, bInsn, ok ? "OK" : "FAIL");
}

// ============================================================================
// ObjC hooks (等价于 Frida Interceptor.attach/replace on ObjC methods)
// ============================================================================

// --- 4. showLaunchScreen -> no-op ---
// 等价于 Frida: Interceptor.replace(impl, new NativeCallback(function(self,cmd){}, 'void', ['pointer','pointer']))
static void showLaunchScreen_replacement(id self, SEL _cmd) {
    NSLog(@"[xinyue] showLaunchScreen BLOCKED");
    // no-op - 不做任何事
}

// --- 5. applyRuntimeState -> 强制 authPassed=YES ---
// 等价于 Frida: Interceptor.attach(impl, { onEnter: function(args){ args[5]=ptr(1); } })
// 方法签名: - (void)applyRuntimeStateWithEnvironmentReady:(BOOL)envReady
//                                              hudRunning:(BOOL)hudRunning
//                                      canExploitLocally:(BOOL)canExploit
//                                                authPassed:(BOOL)authPassed
// ObjC 方法参数布局: args[0]=self, args[1]=_cmd, args[2]=envReady, args[3]=hudRunning,
//                    args[4]=canExploit, args[5]=authPassed
// Frida 中 args[5]=ptr(1) 就是把 authPassed 参数改为 1 (YES)
static void (*applyRuntimeState_original)(id, SEL, BOOL, BOOL, BOOL, BOOL) = NULL;
static void applyRuntimeState_hook(id self, SEL _cmd, BOOL envReady, BOOL hudRunning, BOOL canExploit, BOOL authPassed) {
    NSLog(@"[xinyue] applyRuntimeState -> authPassed forced to YES (was %d)", authPassed);
    if (applyRuntimeState_original) {
        applyRuntimeState_original(self, _cmd, envReady, hudRunning, canExploit, YES);
    }
}

// --- 6. presentViewController -> 拦截卡密弹窗 ---
// 等价于 Frida: Interceptor.attach(impl, { onEnter: function(args){
//   if (clsName === "UIAlertController") { if (title contains keywords) { args[4]=ptr(NULL); } }
// }})
static void (*presentVC_original)(id, SEL, id, BOOL, id) = NULL;
static void presentVC_hook(id self, SEL _cmd, id presentedVC, BOOL animated, id completion) {
    // 检查是否是 UIAlertController
    Class presentedClass = object_getClass(presentedVC);
    Class alertClass = objc_getClass("UIAlertController");
    if (presentedClass == alertClass) {
        // 获取 title
        NSString *title = @"";
        @try { title = [(UIViewController *)presentedVC title] ?: @""; } @catch(id e) {}

        // 检查关键词（心悦、验证、激活、卡密、失败、不存在、输入）
        BOOL shouldBlock = NO;
        NSArray *keywords = @[@"心悦", @"验证", @"激活", @"卡密", @"失败", @"不存在", @"输入"];
        for (NSString *kw in keywords) {
            if ([title containsString:kw]) { shouldBlock = YES; break; }
        }

        if (shouldBlock) {
            NSLog(@"[xinyue] BLOCKING presentation of: %@", title);
            // 等价于 args[4]=ptr(NULL)：把 completion handler 设为 NULL
            presentVC_original(self, _cmd, presentedVC, animated, NULL);
            return;
        }
        NSLog(@"[xinyue] presenting alert (pass-through): %@", title);
    }

    // 正常调用
    presentVC_original(self, _cmd, presentedVC, animated, completion);
}

// --- 7. viewDidAppear -> 自动关闭卡密弹窗 ---
// 等价于 Frida: Interceptor.attach(impl, { onEnter: function(args){
//   if (clsName === "UIAlertController" && title contains keywords) {
//     dispatch_async(main_queue, ^{ [self dismissViewControllerAnimated:YES completion:NULL]; });
//   }
// }})
static void (*viewDidAppear_original)(id, SEL, BOOL) = NULL;
static void viewDidAppear_hook(id self, SEL _cmd, BOOL animated) {
    viewDidAppear_original(self, _cmd, animated);

    // 检查是否是 UIAlertController
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
// 安装 ObjC hooks
// ============================================================================

static void install_objc_hooks(void) {
    NSLog(@"[xinyue] === installing ObjC hooks ===");

    // --- ViewController hooks ---
    Class vcClass = objc_getClass("ViewController");
    if (vcClass) {
        NSLog(@"[xinyue] ViewController found");

        // showLaunchScreen -> no-op
        Method showMethod = class_getInstanceMethod(vcClass, NSSelectorFromString(@"showLaunchScreen"));
        if (showMethod) {
            // 等价于 Interceptor.replace
            method_setImplementation(showMethod, (IMP)showLaunchScreen_replacement);
            NSLog(@"[xinyue] showLaunchScreen replaced no-op");
        }

        // hideLaunchScreen -> pass-through (just log, no change needed)
        // JS 脚本只是 attach 记日志，不改行为，所以我们也不改

        // applyRuntimeState -> force authPassed=YES
        Method applyMethod = class_getInstanceMethod(vcClass,
            NSSelectorFromString(@"applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:"));
        if (applyMethod) {
            IMP origImpl = method_getImplementation(applyMethod);
            applyRuntimeState_original = (void (*)(id, SEL, BOOL, BOOL, BOOL, BOOL))origImpl;
            method_setImplementation(applyMethod, (IMP)applyRuntimeState_hook);
            NSLog(@"[xinyue] applyRuntimeState hooked (force authPassed=YES)");
        }

        // pollActivationThenReveal, refreshAuthSummary, hideLaunchScreen
        // JS 脚本只是 attach 记日志，不改行为，不翻译
    } else {
        NSLog(@"[xinyue] WARNING: ViewController class not found");
    }

    // --- UIViewController hooks (presentViewController, viewDidAppear) ---
    Class uiVCClass = objc_getClass("UIViewController");
    if (uiVCClass) {
        // presentViewController:animated:completion: -> 拦截卡密弹窗
        Method presentMethod = class_getInstanceMethod(uiVCClass,
            NSSelectorFromString(@"presentViewController:animated:completion:"));
        if (presentMethod) {
            IMP origImpl = method_getImplementation(presentMethod);
            presentVC_original = (void (*)(id, SEL, id, BOOL, id))origImpl;
            method_setImplementation(presentMethod, (IMP)presentVC_hook);
            NSLog(@"[xinyue] presentViewController hook installed");
        }

        // viewDidAppear: -> 自动关闭卡密弹窗
        Method viewDidMethod = class_getInstanceMethod(uiVCClass,
            NSSelectorFromString(@"viewDidAppear:"));
        if (viewDidMethod) {
            IMP origImpl = method_getImplementation(viewDidMethod);
            viewDidAppear_original = (void (*)(id, SEL, BOOL))origImpl;
            method_setImplementation(viewDidMethod, (IMP)viewDidAppear_hook);
            NSLog(@"[xinyue] viewDidAppear hook for auto-dismiss");
        }
    }

    // --- UIAlertController init hook (just log, no behavior change) ---
    // JS 脚本只是 attach 记日志，不翻译

    NSLog(@"[xinyue] === ObjC hooks installed ===");
}

// ============================================================================
// 主函数：应用所有 patch 和 hook
// ============================================================================

static void apply_all_patches(void) {
    NSLog(@"[xinyue] === XINYUE crack v6 (complete translation) ===");

    uintptr_t base = get_xyld_base();
    if (base == 0) {
        NSLog(@"[xinyue] ERROR: xyld base not found!");
        return;
    }
    NSLog(@"[xinyue] xyld base: 0x%lx", (unsigned long)base);

    // 假日期字符串已用 CFSTR 常量初始化，无需额外操作

    // ========== 1. C 函数 patch: sub_F14144v -> return 1 ==========
    patch_return_one(base + 0x5cacac, "sub_F14144v");

    // ========== 2. C 函数 patch: _LFVerifyNetworkActivation -> return 1 ==========
    patch_return_one(base + 0x4870, "LFVerifyNetworkActivation");

    // ========== 3. C 函数 patch: LFVerifierExpiryText -> 返回假日期 ==========
    // JS 脚本用 Interceptor.attach onLeave 修改返回值
    // 这里用 B 指令跳转到我们的替代函数
    patch_expiry_text(base + 0x10f00, "LFVerifierExpiryText");

    // ========== 4. C 函数 patch: sub_65D614v -> 跳过弹窗构建 ==========
    patch_skip_dialog(base, 0x58be8, "sub_65D614v skip dialog");

    // ========== 5. ObjC hooks ==========
    install_objc_hooks();

    NSLog(@"[xinyue] === all patches and hooks applied ===");
}

// ============================================================================
// Constructor: 在进程启动时直接同步执行
// ============================================================================
__attribute__((constructor))
static void xinyue_crack_init(void) {
    // 直接同步执行，不用 dispatch_async
    // constructor 执行时机比 main() 和 +load 都早
    apply_all_patches();
}
