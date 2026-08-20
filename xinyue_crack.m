// xinyue_crack.dylib - Self-contained Frida Gadget Injector
//
// 把 frida-gadget.dylib 和 JS 脚本嵌入数据段，
// constructor 中释放到 /tmp/ 并 dlopen 加载，自动执行 hook。
//
// 用户只需注入这一个 dylib 即可完成破解。
//
// 编译时需要：
//   1. frida-gadget.dylib（下载后用 xxd 转成 C 数组到 frida_gadget_data.h）
//   2. FridaGadget.js（用 xxd 转成 C 数组到 frida_js_data.h）
//
// GitHub Actions 会自动处理这些步骤。

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <unistd.h>
#import <string.h>

// 数据段中的嵌入数据（编译时生成）
#include "frida_gadget_data.h"
#include "frida_js_data.h"

// 临时文件路径
// frida-gadget 根据 dylib 文件名查找同名 .config 文件
// 所以 dylib 叫 .frida_gadget.dylib，config 就要叫 .frida_gadget.config
#define GADGET_PATH  "/tmp/.xinyue_gadget.dylib"
#define SCRIPT_PATH  "/tmp/.xinyue_gadget.js"
#define CONFIG_PATH  "/tmp/.xinyue_gadget.config"

// 写入二进制数据到文件
static bool write_file(const char *path, const unsigned char *data, unsigned long size, mode_t mode) {
    // 先删除旧文件
    unlink(path);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        NSLog(@"[xinyue] Failed to create %s: %s", path, strerror(errno));
        return false;
    }

    // 分块写入（大文件需要）
    size_t totalWritten = 0;
    while (totalWritten < size) {
        ssize_t written = write(fd, data + totalWritten, size - totalWritten);
        if (written < 0) {
            if (errno == EINTR) continue;
            NSLog(@"[xinyue] Write failed at %s: %s (wrote %zu/%zu)", path, strerror(errno), totalWritten, size);
            close(fd);
            return false;
        }
        totalWritten += written;
    }
    close(fd);

    chmod(path, mode);
    NSLog(@"[xinyue] Wrote %s (%zu bytes)", path, totalWritten);
    return true;
}

// 生成 frida-gadget 的 config 文件
static bool write_config_file(const char *configPath, const char *scriptPath) {
    // frida-gadget config 中 path 是相对路径（相对于 config 所在目录）
    // 获取 scriptPath 的文件名部分
    const char *scriptName = strrchr(scriptPath, '/');
    if (scriptName) {
        scriptName++;
    } else {
        scriptName = scriptPath;
    }

    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "{\n"
        "  \"interaction\": {\n"
        "    \"type\": \"script\",\n"
        "    \"path\": \"%s\",\n"
        "    \"on_change\": \"reload\"\n"
        "  }\n"
        "}\n",
        scriptName
    );

    if (len <= 0 || (size_t)len >= sizeof(buf)) {
        NSLog(@"[xinyue] Config string too long");
        return false;
    }

    return write_file(configPath, (const unsigned char *)buf, (unsigned long)len, 0644);
}

__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === self-contained crack dylib loaded ===");

        // 1. 释放 frida-gadget.dylib 到 /tmp/
        NSLog(@"[xinyue] Extracting frida-gadget (%u bytes)...", (unsigned int)frida_gadget_data_len);
        if (!write_file(GADGET_PATH, frida_gadget_data, frida_gadget_data_len, 0755)) {
            NSLog(@"[xinyue] FATAL: Cannot extract frida-gadget");
            return;
        }

        // 2. 释放 JS 脚本到 /tmp/
        NSLog(@"[xinyue] Extracting JS script (%u bytes)...", (unsigned int)frida_js_data_len);
        if (!write_file(SCRIPT_PATH, frida_js_data, frida_js_data_len, 0644)) {
            NSLog(@"[xinyue] FATAL: Cannot extract JS script");
            return;
        }

        // 3. 生成 config 文件到 /tmp/
        // frida-gadget 会查找 GADGET_PATH 同名的 .config 文件
        // 即 CONFIG_PATH
        if (!write_config_file(CONFIG_PATH, SCRIPT_PATH)) {
            NSLog(@"[xinyue] FATAL: Cannot create config");
            return;
        }

        // 4. dlopen frida-gadget.dylib
        // frida-gadget 的 constructor 会在 dlopen 时自动执行
        // 它读取 CONFIG_PATH，找到 SCRIPT_PATH 并执行 JS 脚本
        NSLog(@"[xinyue] dlopen(%s)...", GADGET_PATH);

        // 清除之前的 dlerror
        dlerror();
        void *handle = dlopen(GADGET_PATH, RTLD_NOW);
        if (!handle) {
            const char *err = dlerror();
            NSLog(@"[xinyue] FATAL: dlopen failed: %s", err ? err : "unknown error");

            // 如果 dlopen 失败，尝试延迟重试（可能是时机问题）
            NSLog(@"[xinyue] Will retry after short delay...");
            usleep(500000); // 0.5s
            dlerror();
            handle = dlopen(GADGET_PATH, RTLD_NOW);
            if (!handle) {
                err = dlerror();
                NSLog(@"[xinyue] Retry also failed: %s", err ? err : "unknown");
            }
        }

        if (handle) {
            NSLog(@"[xinyue] === frida-gadget loaded successfully ===");
        }
    }
}
