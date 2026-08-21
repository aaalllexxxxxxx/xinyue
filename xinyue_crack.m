// xinyue_crack.dylib - Frida Gadget 方案
//
// 把 frida-gadget.dylib + FridaGadget.js + FridaGadget.config 嵌入数据段
// constructor 中释放到 wrapper dylib 所在目录（TweakInject），然后 dlopen
// TweakInject 目录的签名验证和 xinyue_crack.dylib 一样（ad-hoc 签名通过）
//
// 关键修复：之前释放到沙盒 Library/Caches 目录，dlopen 因签名验证失败
// 现在释放到 wrapper dylib 自己所在目录（TweakInject），签名验证和自身一样

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>

// 嵌入的二进制数据（由 build.yml 中的 Python 脚本生成）
#include "frida_gadget_data.h"
#include "frida_js_data.h"
#include "frida_config_data.h"

static bool write_to_file(const char *path, const unsigned char *data, unsigned long size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        NSLog(@"[xinyue] ERROR: cannot create %s: %s", path, strerror(errno));
        return false;
    }
    ssize_t written = write(fd, data, size);
    close(fd);
    if (written != (ssize_t)size) {
        NSLog(@"[xinyue] ERROR: write incomplete %s: %zd/%lu", path, written, size);
        return false;
    }
    NSLog(@"[xinyue] wrote %s (%lu bytes)", path, size);
    return true;
}

// 获取 wrapper dylib 自身所在目录
static void get_dylib_dir(char *buf, size_t bufsize) {
    // 方法1: 用 dladdr 获取当前函数地址对应的模块路径
    Dl_info info;
    if (dladdr((void *)get_dylib_dir, &info) && info.dli_fname) {
        strncpy(buf, info.dli_fname, bufsize - 1);
        buf[bufsize - 1] = '\0';
        // 去掉文件名，只留目录
        char *lastSlash = strrchr(buf, '/');
        if (lastSlash) {
            *lastSlash = '\0';
        }
        return;
    }

    // 方法2: 遍历已加载模块，找 xinyue_crack
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "xinyue_crack")) {
            strncpy(buf, name, bufsize - 1);
            buf[bufsize - 1] = '\0';
            char *lastSlash = strrchr(buf, '/');
            if (lastSlash) *lastSlash = '\0';
            return;
        }
    }

    // Fallback: 沙盒 Caches 目录
    NSString *cachesDir = NSSearchPathForDirectoriesInDomains(
        NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (cachesDir) {
        strncpy(buf, [cachesDir UTF8String], bufsize - 1);
        buf[bufsize - 1] = '\0';
    }
}

__attribute__((constructor))
static void xinyue_crack_init(void) {
    NSLog(@"[xinyue] === crack dylib init (frida-gadget embedded) ===");

    // 获取 wrapper dylib 自身所在目录
    char dir[1024];
    get_dylib_dir(dir, sizeof(dir));
    NSLog(@"[xinyue] dylib dir: %s", dir);

    // 释放 frida-gadget.dylib
    char gadgetPath[1024];
    snprintf(gadgetPath, sizeof(gadgetPath), "%s/FridaGadget.dylib", dir);
    if (!write_to_file(gadgetPath, frida_gadget_data, frida_gadget_size)) {
        NSLog(@"[xinyue] FATAL: cannot extract FridaGadget.dylib");
        return;
    }

    // 释放 FridaGadget.js
    char jsPath[1024];
    snprintf(jsPath, sizeof(jsPath), "%s/FridaGadget.js", dir);
    if (!write_to_file(jsPath, frida_js_data, frida_js_size)) {
        NSLog(@"[xinyue] FATAL: cannot extract FridaGadget.js");
        return;
    }

    // 释放 FridaGadget.config
    char configPath[1024];
    snprintf(configPath, sizeof(configPath), "%s/FridaGadget.config", dir);
    if (!write_to_file(configPath, frida_config_data, frida_config_size)) {
        NSLog(@"[xinyue] FATAL: cannot extract FridaGadget.config");
        return;
    }

    // dlopen 加载 frida-gadget
    // FridaGadget.dylib 释放到 TweakInject 目录（和 xinyue_crack.dylib 同目录）
    // 这个目录的签名验证和 xinyue_crack.dylib 一样，ad-hoc 签名应该能通过
    dlerror(); // clear
    NSLog(@"[xinyue] dlopen(%s)...", gadgetPath);
    void *handle = dlopen(gadgetPath, RTLD_NOW);
    if (!handle) {
        char *err = dlerror();
        NSLog(@"[xinyue] dlopen FAILED: %s", err ? err : "(unknown)");

        // 尝试 RTLD_LAZY
        dlerror();
        handle = dlopen(gadgetPath, RTLD_LAZY);
        if (handle) {
            NSLog(@"[xinyue] dlopen OK with RTLD_LAZY");
        } else {
            err = dlerror();
            NSLog(@"[xinyue] dlopen RTLD_LAZY also FAILED: %s", err ? err : "(unknown)");
            return;
        }
    }

    NSLog(@"[xinyue] dlopen OK! Frida Gadget loaded.");
    NSLog(@"[xinyue] === crack dylib done ===");
}
