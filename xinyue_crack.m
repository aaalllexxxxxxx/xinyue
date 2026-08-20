// xinyue_gadget.dylib - Frida Gadget loader with embedded JS script
// The JS hook script is embedded in __DATA segment, extracted to a temp file at runtime,
// then frida-gadget.dylib is loaded via dlopen with a generated config pointing to the script.
//
// Build: GitHub Actions downloads frida-gadget.dylib (arm64) and bundles it alongside this dylib.
// Inject both xinyue_gadget.dylib AND frida-gadget.dylib into the target app.
// OR: this dylib dlopen's frida-gadget.dylib from the Frameworks directory.

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <sys/stat.h>

// ============================================================
// Embedded Frida JS hook script (v6) - stored in __DATA segment
// ============================================================

// The script is split into a char array to avoid compiler string length limits
// and ensure it's placed in the binary's data segment.
static const char *kHookScriptParts[] = {
    // Part 1: Helper functions
    "// XINYUE Hook Script v6 - Embedded in dylib\n",
    "var MODULE_NAME = \"xyld\";\n",
    "\n",
    "function getBase() {\n",
    "    var m = Process.findModuleByName(MODULE_NAME);\n",
    "    if (!m) {\n",
    "        var found = null;\n",
    "        Process.enumerateModules().forEach(function(mod) {\n",
    "            if (mod.name === MODULE_NAME || mod.name === \"xyld\") { found = mod; }\n",
    "        });\n",
    "        if (!found) {\n",
    "            Process.enumerateModules().forEach(function(mod) {\n",
    "                if (mod.path && mod.path.indexOf(\"xyld\") !== -1) { found = mod; }\n",
    "            });\n",
    "        }\n",
    "        return found;\n",
    "    }\n",
    "    return m;\n",
    "}\n",
    "\n",
    "function findExport(symbolName) {\n",
    "    var addr = null;\n",
    "    try { addr = Module.getGlobalExportByName(symbolName); } catch(e) {}\n",
    "    if (!addr) {\n",
    "        Process.enumerateModules().forEach(function(mod) {\n",
    "            if (addr) return;\n",
    "            try { addr = mod.getExportByName(symbolName); } catch(e) {}\n",
    "        });\n",
    "    }\n",
    "    return addr;\n",
    "}\n",
    "\n",
    "function tryHookByExport(symbolName, label, hookConfig) {\n",
    "    var addr = findExport(symbolName);\n",
    "    if (addr) {\n",
    "        console.log(\"[+] \" + label + \" export @ \" + addr);\n",
    "        Interceptor.attach(addr, hookConfig);\n",
    "        return true;\n",
    "    }\n",
    "    return false;\n",
    "}\n",
    "\n",
    "function tryHookByOffset(offset, label, hookConfig) {\n",
    "    var mod = getBase();\n",
    "    if (!mod) { console.log(\"[!] No base for \" + label); return false; }\n",
    "    var addr = mod.base.add(offset);\n",
    "    console.log(\"[+] \" + label + \" hook @ \" + addr + \" (base=\" + mod.base + \" + 0x\" + offset.toString(16) + \")\");\n",
    "    Interceptor.attach(addr, hookConfig);\n",
    "    return true;\n",
    "}\n",
    "\n",
    "function tryReplaceByExport(symbolName, label, retval) {\n",
    "    var addr = findExport(symbolName);\n",
    "    if (addr) {\n",
    "        console.log(\"[+] \" + label + \" REPLACED @ \" + addr + \" -> returns \" + retval);\n",
    "        Interceptor.replace(addr, new NativeCallback(function() {\n",
    "            console.log(\"[*] \" + label + \" called -> returning \" + retval);\n",
    "            return retval;\n",
    "        }, 'int', []));\n",
    "        return true;\n",
    "    }\n",
    "    return false;\n",
    "}\n",
    "\n",
    "function tryReplaceByOffset(offset, label, retval) {\n",
    "    var mod = getBase();\n",
    "    if (!mod) { console.log(\"[!] No base for \" + label); return false; }\n",
    "    var addr = mod.base.add(offset);\n",
    "    console.log(\"[+] \" + label + \" REPLACED @ \" + addr + \" -> returns \" + retval);\n",
    "    Interceptor.replace(addr, new NativeCallback(function() {\n",
    "        console.log(\"[*] \" + label + \" called -> returning \" + retval);\n",
    "        return retval;\n",
    "    }, 'int', []));\n",
    "    return true;\n",
    "}\n",
    "\n",
    "function trySkipDialogBuilder(offset, label) {\n",
    "    var mod = getBase();\n",
    "    if (!mod) { console.log(\"[!] No base for \" + label); return false; }\n",
    "    var funcAddr = mod.base.add(offset);\n",
    "    var patchAddr = mod.base.add(offset + 0x08);\n",
    "    var ldpAddr = mod.base.add(offset + 0x88);\n",
    "    var branchImm = (ldpAddr.toInt32() - patchAddr.toInt32()) / 4;\n",
    "    var bInsn = 0x14000000 | (branchImm & 0x03FFFFFF);\n",
    "    console.log(\"[+] \" + label + \" PATCH @ \" + patchAddr + \" -> B \" + ldpAddr + \" (insn=0x\" + bInsn.toString(16) + \")\");\n",
    "    Memory.patchCode(patchAddr, 4, function(code) {\n",
    "        code.writeU32(bInsn);\n",
    "    });\n",
    "    console.log(\"[+] \" + label + \" patched: dialog build skipped, tail-call preserved\");\n",
    "    return true;\n",
    "}\n",
    "\n",
    "console.log(\"\\n=== XINYUE Hook v6 (embedded) ===\\n\");\n",
    "\n",
    // Part 2: Hook installations
    "// 1. REPLACE sub_F14144v\n",
    "var subReplaced = false;\n",
    "subReplaced = tryReplaceByExport(\"_Z10sub_F14144v\", \"sub_F14144v\", 1);\n",
    "if (!subReplaced) { subReplaced = tryReplaceByOffset(0x5cacac, \"sub_F14144v\", 1); }\n",
    "if (!subReplaced) { console.log(\"[!] sub_F14144v replace FAILED\"); }\n",
    "\n",
    "// 2. REPLACE _LFVerifyNetworkActivation\n",
    "var verifyReplaced = false;\n",
    "verifyReplaced = tryReplaceByExport(\"_LFVerifyNetworkActivation\", \"LFVerifyNetworkActivation\", 1);\n",
    "if (!verifyReplaced) { verifyReplaced = tryReplaceByOffset(0x4870, \"LFVerifyNetworkActivation\", 1); }\n",
    "if (!verifyReplaced) { console.log(\"[!] LFVerifyNetworkActivation replace FAILED\"); }\n",
    "\n",
    "// 3. Hook LFVerifierExpiryText\n",
    "var expiryHooked = false;\n",
    "if (!expiryHooked) {\n",
    "    expiryHooked = tryHookByExport(\"_ZL20LFVerifierExpiryTextv\", \"LFVerifierExpiryText\", {\n",
    "        onEnter: function(args) {},\n",
    "        onLeave: function(retval) {\n",
    "            if (retval.isNull()) {\n",
    "                var fakeStr = ObjC.classes.NSString.stringWithString_(\"2099-12-31 23:59:59\");\n",
    "                retval.replace(fakeStr);\n",
    "            }\n",
    "        }\n",
    "    });\n",
    "}\n",
    "if (!expiryHooked) {\n",
    "    expiryHooked = tryHookByOffset(0x10f00, \"LFVerifierExpiryText\", {\n",
    "        onEnter: function(args) {},\n",
    "        onLeave: function(retval) {\n",
    "            if (retval.isNull()) {\n",
    "                var fakeStr = ObjC.classes.NSString.stringWithString_(\"2099-12-31 23:59:59\");\n",
    "                retval.replace(fakeStr);\n",
    "            }\n",
    "        }\n",
    "    });\n",
    "}\n",
    "\n",
    "// 4. SKIP sub_65D614v dialog builder\n",
    "var cdkeyDialogSkipped = false;\n",
    "cdkeyDialogSkipped = trySkipDialogBuilder(0x58be8, \"sub_65D614v (CDKey dialog builder)\");\n",
    "\n",
    "// 5. ObjC hooks\n",
    "if (ObjC.available) {\n",
    "    var cls = ObjC.classes.ViewController;\n",
    "    if (cls) {\n",
    "        console.log(\"[+] ViewController found\");\n",
    "        if (cls[\"- pollActivationThenReveal\"]) {\n",
    "            Interceptor.attach(cls[\"- pollActivationThenReveal\"].implementation, {\n",
    "                onEnter: function(args) { console.log(\"[*] pollActivationThenReveal\"); }\n",
    "            });\n",
    "        }\n",
    "        if (cls[\"- showLaunchScreen\"]) {\n",
    "            Interceptor.replace(cls[\"- showLaunchScreen\"].implementation, new NativeCallback(function(self, cmd) {\n",
    "                console.log(\"[*] showLaunchScreen BLOCKED\");\n",
    "            }, 'void', ['pointer', 'pointer']));\n",
    "            console.log(\"[+] showLaunchScreen replaced no-op\");\n",
    "        }\n",
    "        if (cls[\"- hideLaunchScreen\"]) {\n",
    "            Interceptor.attach(cls[\"- hideLaunchScreen\"].implementation, {\n",
    "                onEnter: function(args) { console.log(\"[*] hideLaunchScreen -> passed!\"); }\n",
    "            });\n",
    "        }\n",
    "        if (cls[\"- applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:\"]) {\n",
    "            Interceptor.attach(cls[\"- applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:\"].implementation, {\n",
    "                onEnter: function(args) {\n",
    "                    console.log(\"[*] applyRuntimeState -> authPassed=1\");\n",
    "                    args[5] = ptr(1);\n",
    "                }\n",
    "            });\n",
    "        }\n",
    "        if (cls[\"- refreshAuthSummary\"]) {\n",
    "            Interceptor.attach(cls[\"- refreshAuthSummary\"].implementation, {\n",
    "                onEnter: function(args) { console.log(\"[*] refreshAuthSummary\"); }\n",
    "            });\n",
    "        }\n",
    "    }\n",
    "\n",
    "    // 6. Network monitoring\n",
    "    var NSURLSession = ObjC.classes.NSURLSession;\n",
    "    if (NSURLSession && NSURLSession[\"- dataTaskWithRequest:completionHandler:\"]) {\n",
    "        Interceptor.attach(NSURLSession[\"- dataTaskWithRequest:completionHandler:\"].implementation, {\n",
    "            onEnter: function(args) {\n",
    "                var req = new ObjC.Object(args[2]);\n",
    "                var url = \"\";\n",
    "                try { url = req.URL() ? req.URL().absoluteString().toString() : \"(null)\"; } catch(e) {}\n",
    "                var method = \"\";\n",
    "                try { method = req.HTTPMethod() ? req.HTTPMethod().toString() : \"GET\"; } catch(e) {}\n",
    "                console.log(\"[NET] \" + method + \" \" + url);\n",
    "            }\n",
    "        });\n",
    "        console.log(\"[+] NSURLSession network hook installed\");\n",
    "    }\n",
    "\n",
    "    // 7. Hook UIAlertController - dismiss ALL alerts\n",
    "    var uiViewController = ObjC.classes.UIViewController;\n",
    "    if (uiViewController && uiViewController[\"- presentViewController:animated:completion:\"]) {\n",
    "        Interceptor.attach(uiViewController[\"- presentViewController:animated:completion:\"].implementation, {\n",
    "            onEnter: function(args) {\n",
    "                var presentedVC = new ObjC.Object(args[2]);\n",
    "                var clsName = presentedVC.$className;\n",
    "                if (clsName === \"UIAlertController\") {\n",
    "                    var title = \"\";\n",
    "                    try { title = presentedVC.title() ? presentedVC.title().toString() : \"\"; } catch(e) {}\n",
    "                    console.log(\"[*] Presenting UIAlertController: \" + title);\n",
    "                    if (title && (title.indexOf(\"\\u5fc3\\u60a6\") !== -1 || title.indexOf(\"\\u9a8c\\u8bc1\") !== -1 ||\n",
    "                        title.indexOf(\"\\u6fc0\\u6d3b\") !== -1 || title.indexOf(\"\\u5361\\u5bc6\") !== -1 ||\n",
    "                        title.indexOf(\"\\u5931\\u8d25\") !== -1 || title.indexOf(\"\\u4e0d\\u5b58\\u5728\") !== -1 ||\n",
    "                        title.indexOf(\"\\u8f93\\u5165\") !== -1)) {\n",
    "                        console.log(\"[*] BLOCKING presentation of: \" + title);\n",
    "                        args[4] = ptr(NULL);\n",
    "                    }\n",
    "                }\n",
    "            }\n",
    "        });\n",
    "        console.log(\"[+] presentViewController hook installed\");\n",
    "    }\n",
    "\n",
    "    if (uiViewController && uiViewController[\"- viewDidAppear:\"]) {\n",
    "        Interceptor.attach(uiViewController[\"- viewDidAppear:\"].implementation, {\n",
    "            onEnter: function(args) {\n",
    "                var self = new ObjC.Object(args[0]);\n",
    "                var clsName = self.$className;\n",
    "                if (clsName === \"UIAlertController\") {\n",
    "                    var title = \"\";\n",
    "                    try { title = self.title() ? self.title().toString() : \"\"; } catch(e) {}\n",
    "                    console.log(\"[*] UIAlertController viewDidAppear: \" + title);\n",
    "                    if (title && (title.indexOf(\"\\u5fc3\\u60a6\") !== -1 || title.indexOf(\"\\u9a8c\\u8bc1\") !== -1 ||\n",
    "                        title.indexOf(\"\\u6fc0\\u6d3b\") !== -1 || title.indexOf(\"\\u5361\\u5bc6\") !== -1 ||\n",
    "                        title.indexOf(\"\\u5931\\u8d25\") !== -1 || title.indexOf(\"\\u4e0d\\u5b58\\u5728\") !== -1 ||\n",
    "                        title.indexOf(\"\\u8f93\\u5165\") !== -1)) {\n",
    "                        console.log(\"[*] Auto-dismissing: \" + title);\n",
    "                        var dispatch_async = new NativeFunction(\n",
    "                            Module.getGlobalExportByName('dispatch_async'),\n",
    "                            'void', ['pointer', 'pointer']\n",
    "                        );\n",
    "                        var dispatch_get_main_queue = new NativeFunction(\n",
    "                            Module.getGlobalExportByName('dispatch_get_main_queue'),\n",
    "                            'pointer', []\n",
    "                        );\n",
    "                        var block = new ObjC.Block({\n",
    "                            rettype: 'void',\n",
    "                            argtypes: [],\n",
    "                            implementation: function() {\n",
    "                                self.dismissViewControllerAnimated_completion_(true, NULL);\n",
    "                            }\n",
    "                        });\n",
    "                        dispatch_async(dispatch_get_main_queue(), block);\n",
    "                    }\n",
    "                }\n",
    "            }\n",
    "        });\n",
    "        console.log(\"[+] viewDidAppear hook for auto-dismiss\");\n",
    "    }\n",
    "\n",
    "    var alertControllerCls = ObjC.classes.UIAlertController;\n",
    "    if (alertControllerCls && alertControllerCls[\"- initWithTitle:message:preferredStyle:\"]) {\n",
    "        Interceptor.attach(alertControllerCls[\"- initWithTitle:message:preferredStyle:\"].implementation, {\n",
    "            onEnter: function(args) {\n",
    "                var title = \"\";\n",
    "                try { title = new ObjC.Object(args[2]).toString(); } catch(e) {}\n",
    "                var message = \"\";\n",
    "                try { message = new ObjC.Object(args[3]).toString(); } catch(e) {}\n",
    "                console.log(\"[ALERT] initWithTitle: \" + title + \" message: \" + message);\n",
    "            }\n",
    "        });\n",
    "        console.log(\"[+] UIAlertController init hook installed\");\n",
    "    }\n",
    "}\n",
    "\n",
    "console.log(\"\\n=== All hooks v6 installed (embedded) ===\\n\");\n",
    NULL
};

// Reassemble the script parts into a single string
static NSString *getEmbeddedScript(void) {
    NSMutableString *script = [NSMutableString string];
    for (int i = 0; kHookScriptParts[i] != NULL; i++) {
        [script appendString:[NSString stringWithUTF8String:kHookScriptParts[i]]];
    }
    return [script copy];
}

// ============================================================
// Extract embedded script to a temp file and set up Frida Gadget
// ============================================================
__attribute__((constructor))
static void xinyue_gadget_init(void) {
    @autoreleasepool {
        NSLog(@"[xinyue-gadget] === Loader starting ===");

        // Step 1: Get writable directory (app's Documents or tmp)
        NSString *scriptDir = nil;

        // Try NSTemporaryDirectory first
        NSString *tmpDir = NSTemporaryDirectory();
        if (tmpDir) {
            scriptDir = tmpDir;
        }

        // Try Documents directory as fallback
        if (!scriptDir) {
            NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
            if (paths.count > 0) {
                scriptDir = paths[0];
            }
        }

        if (!scriptDir) {
            NSLog(@"[xinyue-gadget] ERROR: No writable directory found");
            return;
        }

        NSLog(@"[xinyue-gadget] Script dir: %@", scriptDir);

        // Step 2: Write embedded JS script to file
        NSString *scriptPath = [scriptDir stringByAppendingPathComponent:@"xinyue_hook.js"];
        NSString *scriptContent = getEmbeddedScript();
        NSError *writeError = nil;
        BOOL ok = [scriptContent writeToFile:scriptPath atomically:YES encoding:NSUTF8StringEncoding error:&writeError];
        if (!ok || writeError) {
            NSLog(@"[xinyue-gadget] ERROR: Failed to write script: %@", writeError);
            return;
        }
        NSLog(@"[xinyue-gadget] Script written to: %@", scriptPath);

        // Step 3: Write Frida Gadget config file
        // Config tells Gadget to load our script in "script" interaction mode
        NSString *configPath = [scriptDir stringByAppendingPathComponent:@"FridaGadget.config"];
        NSDictionary *config = @{
            @"interaction": @{
                @"type": @"script",
                @"path": scriptPath,
                @"on_change": @"reload"
            }
        };
        NSData *configData = [NSJSONSerialization dataWithJSONObject:config options:0 error:nil];
        NSString *configStr = [[NSString alloc] initWithData:configData encoding:NSUTF8StringEncoding];
        [configStr writeToFile:configPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"[xinyue-gadget] Config written to: %@", configPath);

        // Step 4: Find and dlopen frida-gadget.dylib
        // Search common locations
        NSArray *searchPaths = @[
            // Same directory as this dylib (Frameworks/)
            @"@executable_path/Frameworks/frida-gadget.dylib",
            @"@rpath/frida-gadget.dylib",
            @"@executable_path/Frameworks/libfrida-gadget.dylib",
            // Absolute paths for jailbreak
            @"/Library/MobileSubstrate/DynamicLibraries/frida-gadget.dylib",
            @"/usr/lib/frida-gadget.dylib",
            // tmp dir (where we might have copied it)
            [scriptDir stringByAppendingPathComponent:@"frida-gadget.dylib"],
        ];

        void *gadgetHandle = NULL;
        for (NSString *path in searchPaths) {
            NSLog(@"[xinyue-gadget] Trying: %@", path);
            gadgetHandle = dlopen([path UTF8String], RTLD_NOW);
            if (gadgetHandle) {
                NSLog(@"[xinyue-gadget] Loaded frida-gadget from: %@", path);
                break;
            }
        }

        if (!gadgetHandle) {
            const char *err = dlerror();
            NSLog(@"[xinyue-gadget] WARNING: frida-gadget.dylib not found. Will retry on next runloop. dlerror: %s", err ? err : "(null)");

            // Retry on next runloop tick (gadget might be loaded later by LC_LOAD_DYLIB)
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                NSLog(@"[xinyue-gadget] Retrying dlopen...");
                void *handle = NULL;
                for (NSString *path in searchPaths) {
                    handle = dlopen([path UTF8String], RTLD_NOW);
                    if (handle) {
                        NSLog(@"[xinyue-gadget] Loaded frida-gadget (retry) from: %@", path);
                        break;
                    }
                }
                if (!handle) {
                    NSLog(@"[xinyue-gadget] FAILED: frida-gadget.dylib not found anywhere. Make sure it's injected alongside this dylib.");
                }
            });
            return;
        }

        NSLog(@"[xinyue-gadget] === Frida Gadget loaded, script injected ===");
    }
}
