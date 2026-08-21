// xinyue_crack.dylib - Frida Gadget 内嵌方案
//
// 把 frida-gadget.dylib + FridaGadget.js + FridaGadget.config 嵌入数据段
// constructor 中释放到沙盒目录并 dlopen 加载
// frida-gadget 会自动读取同目录的 .config 和 .js 执行 hook 脚本

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <sys/stat.h>

// 嵌入的二进制数据（由 build.yml 中的 Python 脚本生成）
#include "frida_gadget_data.h"
#include "frida_js_data.h"
#include "frida_config_data.h"

// 释放嵌入数据到文件
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

__attribute__((constructor))
static void xinyue_crack_init(void) {
    NSLog(@"[xinyue] === crack dylib loading (frida-gadget embedded) ===");

    // 获取沙盒 Library/Caches 目录
    NSString *cachesDir = NSSearchPathForDirectoriesInDomains(
        NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (!cachesDir) {
        NSLog(@"[xinyue] FATAL: cannot get caches directory");
        return;
    }

    const char *dir = [cachesDir UTF8String];
    NSLog(@"[xinyue] sandbox dir: %s", dir);

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
    NSLog(@"[xinyue] dlopen(%s)...", gadgetPath);
    void *handle = dlopen(gadgetPath, RTLD_NOW);
    if (!handle) {
        char *err = dlerror();
        NSLog(@"[xinyue] dlopen FAILED: %s", err ? err : "(unknown)");
        return;
    }

    NSLog(@"[xinyue] dlopen OK! Frida Gadget loaded.");
    NSLog(@"[xinyue] === crack dylib done ===");
}
