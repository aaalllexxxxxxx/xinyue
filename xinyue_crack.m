// xinyue_crack.dylib - Frida Gadget 内嵌方案
//
// 把 frida-gadget.dylib + FridaGadget.js + FridaGadget.config 嵌入数据段
// constructor 中释放到沙盒目录，用 ldid 重签名后 dlopen 加载
// frida-gadget 会自动读取同目录的 .config 和 .js 执行 hook 脚本

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <spawn.h>

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

// 用 ldid 重签名 dylib（越狱环境）
static void resign_dylib(const char *path) {
    // 尝试用 ldid -S 重签名
    pid_t pid;
    char *argv[] = {"ldid", "-S", (char *)path, NULL};
    extern char **environ;
    int status;
    int err = posix_spawn(&pid, "/usr/bin/ldid", NULL, NULL, argv, environ);
    if (err != 0) {
        // ldid 可能不在 /usr/bin，尝试 PATH 查找
        err = posix_spawnp(&pid, "ldid", NULL, NULL, argv, environ);
    }
    if (err == 0) {
        waitpid(pid, &status, 0);
        NSLog(@"[xinyue] ldid resign status=%d", status);
    } else {
        NSLog(@"[xinyue] ldid not found (%d), trying codesign", err);
        // 尝试 codesign
        char *argv2[] = {"codesign", "-f", "-s", "-", (char *)path, NULL};
        err = posix_spawnp(&pid, "codesign", NULL, NULL, argv2, environ);
        if (err == 0) {
            waitpid(pid, &status, 0);
            NSLog(@"[xinyue] codesign resign status=%d", status);
        } else {
            NSLog(@"[xinyue] codesign also not found (%d)", err);
        }
    }
    // 设置可执行权限
    chmod(path, 0755);
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

    // 重签名 frida-gadget（释放后签名可能失效）
    NSLog(@"[xinyue] resigning FridaGadget.dylib...");
    resign_dylib(gadgetPath);

    // 清除 dlerror
    dlerror();

    // dlopen 加载 frida-gadget
    NSLog(@"[xinyue] dlopen(%s)...", gadgetPath);
    void *handle = dlopen(gadgetPath, RTLD_NOW);
    if (!handle) {
        char *err = dlerror();
        NSLog(@"[xinyue] dlopen FAILED: %s", err ? err : "(unknown)");

        // 尝试用 RTLD_LAZY
        dlerror();
        handle = dlopen(gadgetPath, RTLD_LAZY);
        if (handle) {
            NSLog(@"[xinyue] dlopen OK with RTLD_LAZY!");
        } else {
            err = dlerror();
            NSLog(@"[xinyue] dlopen RTLD_LAZY also FAILED: %s", err ? err : "(unknown)");
            return;
        }
    }

    NSLog(@"[xinyue] dlopen OK! Frida Gadget loaded.");
    NSLog(@"[xinyue] === crack dylib done ===");
}
