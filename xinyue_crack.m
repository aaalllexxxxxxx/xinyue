// xinyue_crack.dylib - Pure ObjC implementation of hook_activation.js v6
//
// 只做 3 个 C 函数 patch（和 Frida 的 Memory.patchCode/Interceptor.replace 等价）
// 不做 ObjC hook（之前 class_replaceMethod 导致闪退）
// 延迟到 main queue 执行（确保所有模块加载完成）
//
// 3 个核心 patch：
//   1. _LFVerifyNetworkActivation -> MOV W0,#1; RET  (验证始终成功)
//   2. sub_F14144v -> MOV W0,#1; RET                (验证子函数始终成功)
//   3. sub_65D614v -> B 指令跳过弹窗构建            (无卡密弹窗)

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <dispatch/dispatch.h>

extern void sys_icache_invalidate(void *address, size_t size);

// 内存 patch - 等价于 Frida 的 Memory.patchCode
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
    // Restore RX (remove W)
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

// Patch: 让函数直接返回 1
// ARM64: MOV W0, #1 (0x52800020) ; RET (0xD65F03C0)
// 等价于 Frida: Interceptor.replace(addr, new NativeCallback(function(){return 1}, 'int', []))
static void patch_return_one(uintptr_t addr, const char *label) {
    uint32_t insns[2] = { 0x52800020, 0xD65F03C0 };
    bool ok = patch_memory(addr, insns, sizeof(insns));
    NSLog(@"[xinyue] %s @ 0x%lx -> MOV W0,#1; RET [%s]", label, (unsigned long)addr, ok ? "OK" : "FAIL");
}

// Patch: 跳过弹窗构建，保留 tail-call
// 等价于 Frida v6: Memory.patchCode 写 B 指令
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
    int32_t imm = (int32_t)(targetAddr - patchAddr) / 4;
    uint32_t bInsn = 0x14000000U | ((uint32_t)imm & 0x03FFFFFFU);
    bool ok = patch_memory(patchAddr, &bInsn, 4);
    NSLog(@"[xinyue] %s @ 0x%lx -> B 0x%lx (0x%08x) [%s]",
          label, (unsigned long)patchAddr, (unsigned long)targetAddr, bInsn, ok ? "OK" : "FAIL");
}

// 所有 patch 逻辑
static void apply_all_patches(void) {
    NSLog(@"[xinyue] === applying patches ===");

    uintptr_t base = get_xyld_base();
    if (base == 0) {
        NSLog(@"[xinyue] ERROR: xyld base not found, retrying...");
        // 延迟重试
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            apply_all_patches();
        });
        return;
    }
    NSLog(@"[xinyue] xyld base: 0x%lx", (unsigned long)base);

    // 1. _LFVerifyNetworkActivation (offset 0x4870) -> return 1
    patch_return_one(base + 0x4870, "LFVerifyNetworkActivation");

    // 2. sub_F14144v (offset 0x5cacac) -> return 1
    patch_return_one(base + 0x5cacac, "sub_F14144v");

    // 3. sub_65D614v (offset 0x58be8) -> skip dialog builder
    patch_skip_dialog(base, 0x58be8, "sub_65D614v skip dialog");

    NSLog(@"[xinyue] === all patches applied ===");
}

__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === crack dylib loaded ===");

        // 延迟到 main queue 执行，确保所有模块已加载
        // Frida 脚本是在进程启动后才执行的，这里也模拟同样的时机
        dispatch_async(dispatch_get_main_queue(), ^{
            apply_all_patches();
        });
    }
}
