// xinyue_crack.dylib - Self-contained Frida Gadget Injector
//
// 把 frida-gadget.dylib（已签名）和 JS 脚本嵌入数据段，
// constructor 中释放到 App 沙盒目录并 dlopen 加载，自动执行 hook。
//
// 用户只需注入这一个 dylib 即可完成破解。
//
// 编译时：
//   1. 下载 frida-gadget，lipo 提取 arm64，ldid -S 签名
//   2. 用 Python 脚本把签名后的 frida-gadget 转为 C 数组 (frida_gadget_data.h)
//   3. 把 FridaGadget.js 转为 C 数组 (frida_js_data.h)
//   4. clang 编译

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <unistd.h>
#import <string.h>

// 数据段中的嵌入数据（编译时生成）
// frida_gadget_data 已包含 ad-hoc 签名
#include "frida_gadget_data.h"
#include "frida_js_data.h"

// 写入数据到文件
static bool write_file(const char *path, const unsigned char *data, unsigned long size, mode_t mode) {
    unlink(path);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        NSLog(@"[xinyue] Failed to create %s: %s", path, strerror(errno));
        return false;
    }

    size_t totalWritten = 0;
    while (totalWritten < size) {
        ssize_t written = write(fd, data + totalWritten, size - totalWritten);
        if (written < 0) {
            if (errno == EINTR) continue;
            NSLog(@"[xinyue] Write failed %s: %s (%zu/%zu)", path, strerror(errno), totalWritten, size);
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

// 生成 frida-gadget config 文件
static bool write_config_file(const char *configPath, const char *scriptName) {
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
    if (len <= 0 || (size_t)len >= sizeof(buf)) return false;
    return write_file(configPath, (const unsigned char *)buf, (unsigned long)len, 0644);
}

__attribute__((constructor))
static void xinyue_crack_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue] === self-contained crack dylib loaded ===");

        // 1. 获取 App 沙盒可写目录
        NSString *cachesDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches"];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:cachesDir withIntermediateDirectories:YES attributes:nil error:nil];
        const char *dir = [cachesDir UTF8String];
        NSLog(@"[xinyue] Release dir: %s", dir);

        // 2. 构建路径
        char gadgetPath[1024], scriptPath[1024], configPath[1024];
        snprintf(gadgetPath,   sizeof(gadgetPath),   "%s/.xinyue_gadget.dylib", dir);
        snprintf(scriptPath,   sizeof(scriptPath),   "%s/.xinyue_gadget.js",    dir);
        snprintf(configPath,   sizeof(configPath),   "%s/.xinyue_gadget.config", dir);

        // 3. 释放 frida-gadget（已在编译时签名）
        NSLog(@"[xinyue] Extracting frida-gadget (%u bytes)...", (unsigned int)frida_gadget_data_len);
        if (!write_file(gadgetPath, frida_gadget_data, frida_gadget_data_len, 0755)) {
            NSLog(@"[xinyue] FATAL: Cannot extract frida-gadget");
            return;
        }

        // 4. 释放 JS 脚本
        NSLog(@"[xinyue] Extracting JS script (%u bytes)...", (unsigned int)frida_js_data_len);
        if (!write_file(scriptPath, frida_js_data, frida_js_data_len, 0644)) {
            NSLog(@"[xinyue] FATAL: Cannot extract JS script");
            return;
        }

        // 5. 生成 config（frida-gadget 根据 dylib 文件名查找同名 .config）
        if (!write_config_file(configPath, ".xinyue_gadget.js")) {
            NSLog(@"[xinyue] FATAL: Cannot create config");
            return;
        }

        // 6. dlopen frida-gadget
        // frida-gadget constructor 会读取 config → 找到 JS → 执行 hook
        NSLog(@"[xinyue] dlopen(%s)...", gadgetPath);

        dlerror();
        void *handle = dlopen(gadgetPath, RTLD_NOW);
        if (!handle) {
            const char *err = dlerror();
            NSLog(@"[xinyue] dlopen failed: %s", err ? err : "unknown");

            // 重试
            NSLog(@"[xinyue] Retrying...");
            usleep(500000);
            dlerror();
            handle = dlopen(gadgetPath, RTLD_NOW);
            if (!handle) {
                err = dlerror();
                NSLog(@"[xinyue] Retry failed: %s", err ? err : "unknown");
            }
        }

        if (handle) {
            NSLog(@"[xinyue] === frida-gadget loaded ===");
        }
    }
}
