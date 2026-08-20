// XINYUE Hook Script v6 - Fix crash on restart by preserving tail-call
var MODULE_NAME = "xyld";

function getBase() {
    var m = Process.findModuleByName(MODULE_NAME);
    if (!m) {
        var found = null;
        Process.enumerateModules().forEach(function(mod) {
            if (mod.name === MODULE_NAME || mod.name === "xyld") { found = mod; }
        });
        if (!found) {
            Process.enumerateModules().forEach(function(mod) {
                if (mod.path && mod.path.indexOf("xyld") !== -1) { found = mod; }
            });
        }
        return found;
    }
    return m;
}

function findExport(symbolName) {
    var addr = null;
    try { addr = Module.getGlobalExportByName(symbolName); } catch(e) {}
    if (!addr) {
        Process.enumerateModules().forEach(function(mod) {
            if (addr) return;
            try { addr = mod.getExportByName(symbolName); } catch(e) {}
        });
    }
    return addr;
}

function tryHookByExport(symbolName, label, hookConfig) {
    var addr = findExport(symbolName);
    if (addr) {
        console.log("[+] " + label + " export @ " + addr);
        Interceptor.attach(addr, hookConfig);
        return true;
    }
    return false;
}

function tryHookByOffset(offset, label, hookConfig) {
    var mod = getBase();
    if (!mod) { console.log("[!] No base for " + label); return false; }
    var addr = mod.base.add(offset);
    console.log("[+] " + label + " hook @ " + addr + " (base=" + mod.base + " + 0x" + offset.toString(16) + ")");
    Interceptor.attach(addr, hookConfig);
    return true;
}

function tryReplaceByExport(symbolName, label, retval) {
    var addr = findExport(symbolName);
    if (addr) {
        console.log("[+] " + label + " REPLACED @ " + addr + " -> returns " + retval);
        Interceptor.replace(addr, new NativeCallback(function() {
            console.log("[*] " + label + " called -> returning " + retval);
            return retval;
        }, 'int', []));
        return true;
    }
    return false;
}

function tryReplaceByOffset(offset, label, retval) {
    var mod = getBase();
    if (!mod) { console.log("[!] No base for " + label); return false; }
    var addr = mod.base.add(offset);
    console.log("[+] " + label + " REPLACED @ " + addr + " -> returns " + retval);
    Interceptor.replace(addr, new NativeCallback(function() {
        console.log("[*] " + label + " called -> returning " + retval);
        return retval;
    }, 'int', []));
    return true;
}

// Skip dialog builder but preserve tail-call to sub_94E80Dv
// sub_65D614v structure:
//   0x00: STP X29,X30,[SP,#-0x10]!  (build stack frame)
//   0x04: MOV X29, SP
//   0x08..0x84: dialog building calls (title, message, buttons, etc.)
//   0x88: LDP X29,X30,[SP],#0x10     (restore stack frame)
//   0x8C: B sub_94E80Dv              (tail-call to ImGui renderer)
// We patch offset 0x08 (after STP+MOV) to jump directly to 0x88 (LDP)
// This preserves stack frame balance and the tail-call
function trySkipDialogBuilder(offset, label) {
    var mod = getBase();
    if (!mod) { console.log("[!] No base for " + label); return false; }
    var funcAddr = mod.base.add(offset);
    // After STP (4 bytes) + MOV (4 bytes), patch at offset+8 to jump to offset+0x88
    var patchAddr = mod.base.add(offset + 0x08);
    var ldpAddr = mod.base.add(offset + 0x88);
    
    // Calculate branch distance: target - patchAddr, in instructions (divide by 4)
    var branchImm = (ldpAddr.toInt32() - patchAddr.toInt32()) / 4;
    // ARM64 B instruction: 0x14000000 | (imm26 & 0x3FFFFFF)
    var bInsn = 0x14000000 | (branchImm & 0x03FFFFFF);
    
    console.log("[+] " + label + " PATCH @ " + patchAddr + " -> B " + ldpAddr + " (insn=0x" + bInsn.toString(16) + ")");
    Memory.patchCode(patchAddr, 4, function(code) {
        code.writeU32(bInsn);
    });
    console.log("[+] " + label + " patched: dialog build skipped, tail-call preserved");
    return true;
}

console.log("\n=== XINYUE Hook v6 ===\n");

// ========== 1. REPLACE sub_F14144v - always return 1 ==========
var subReplaced = false;
subReplaced = tryReplaceByExport("_Z10sub_F14144v", "sub_F14144v", 1);
if (!subReplaced) {
    subReplaced = tryReplaceByOffset(0x5cacac, "sub_F14144v", 1);
}
if (!subReplaced) { console.log("[!] sub_F14144v replace FAILED"); }

// ========== 2. REPLACE _LFVerifyNetworkActivation - always return 1 ==========
var verifyReplaced = false;
verifyReplaced = tryReplaceByExport("_LFVerifyNetworkActivation", "LFVerifyNetworkActivation", 1);
if (!verifyReplaced) {
    verifyReplaced = tryReplaceByOffset(0x4870, "LFVerifyNetworkActivation", 1);
}
if (!verifyReplaced) { console.log("[!] LFVerifyNetworkActivation replace FAILED"); }

// ========== 3. Hook LFVerifierExpiryText ==========
var expiryHooked = false;
if (!expiryHooked) {
    expiryHooked = tryHookByExport("_ZL20LFVerifierExpiryTextv", "LFVerifierExpiryText", {
        onEnter: function(args) {},
        onLeave: function(retval) {
            if (retval.isNull()) {
                var fakeStr = ObjC.classes.NSString.stringWithString_("2099-12-31 23:59:59");
                retval.replace(fakeStr);
            }
        }
    });
}
if (!expiryHooked) {
    expiryHooked = tryHookByOffset(0x10f00, "LFVerifierExpiryText", {
        onEnter: function(args) {},
        onLeave: function(retval) {
            if (retval.isNull()) {
                var fakeStr = ObjC.classes.NSString.stringWithString_("2099-12-31 23:59:59");
                retval.replace(fakeStr);
            }
        }
    });
}

// ========== 4. SKIP sub_65D614v dialog builder but preserve tail-call ==========
// sub_65D614v builds the "心悦漏打" CDKey dialog, then tail-calls sub_94E80Dv (ImGui renderer)
// We skip the dialog-building body (jump to LDP X29,X30 instruction) but keep the tail-call
// This prevents crash on restart caused by missing sub_94E80Dv execution
var cdkeyDialogSkipped = false;
cdkeyDialogSkipped = trySkipDialogBuilder(0x58be8, "sub_65D614v (CDKey dialog builder)");

// ========== 5. ObjC hooks ==========
if (ObjC.available) {
    var cls = ObjC.classes.ViewController;
    if (cls) {
        console.log("[+] ViewController found");

        if (cls["- pollActivationThenReveal"]) {
            Interceptor.attach(cls["- pollActivationThenReveal"].implementation, {
                onEnter: function(args) { console.log("[*] pollActivationThenReveal"); }
            });
        }

        if (cls["- showLaunchScreen"]) {
            Interceptor.replace(cls["- showLaunchScreen"].implementation, new NativeCallback(function(self, cmd) {
                console.log("[*] showLaunchScreen BLOCKED");
            }, 'void', ['pointer', 'pointer']));
            console.log("[+] showLaunchScreen replaced no-op");
        }

        if (cls["- hideLaunchScreen"]) {
            Interceptor.attach(cls["- hideLaunchScreen"].implementation, {
                onEnter: function(args) { console.log("[*] hideLaunchScreen -> passed!"); }
            });
        }

        if (cls["- applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:"]) {
            Interceptor.attach(cls["- applyRuntimeStateWithEnvironmentReady:hudRunning:canExploitLocally:authPassed:"].implementation, {
                onEnter: function(args) {
                    console.log("[*] applyRuntimeState -> authPassed=1");
                    args[5] = ptr(1);
                }
            });
        }

        if (cls["- refreshAuthSummary"]) {
            Interceptor.attach(cls["- refreshAuthSummary"].implementation, {
                onEnter: function(args) { console.log("[*] refreshAuthSummary"); }
            });
        }
    }

    // ========== 6. Network monitoring ==========
    var NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession && NSURLSession["- dataTaskWithRequest:completionHandler:"]) {
        Interceptor.attach(NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
            onEnter: function(args) {
                var req = new ObjC.Object(args[2]);
                var url = "";
                try { url = req.URL() ? req.URL().absoluteString().toString() : "(null)"; } catch(e) {}
                var method = "";
                try { method = req.HTTPMethod() ? req.HTTPMethod().toString() : "GET"; } catch(e) {}
                console.log("[NET] " + method + " " + url);
            }
        });
        console.log("[+] NSURLSession network hook installed");
    }

    var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    if (NSMutableURLRequest && NSMutableURLRequest["+ requestWithURL:"]) {
        Interceptor.attach(NSMutableURLRequest["+ requestWithURL:"].implementation, {
            onEnter: function(args) {
                var url = new ObjC.Object(args[2]);
                console.log("[NET] requestWithURL: " + url.absoluteString().toString());
            }
        });
    }

    // ========== 7. Hook UIAlertController - dismiss ALL alerts ==========
    // Since the CDKey dialog shows as "心悦漏打" and "验证失败",
    // we hook UIAlertController presentation to dismiss them immediately
    var uiViewController = ObjC.classes.UIViewController;
    if (uiViewController && uiViewController["- presentViewController:animated:completion:"]) {
        Interceptor.attach(uiViewController["- presentViewController:animated:completion:"].implementation, {
            onEnter: function(args) {
                var presentedVC = new ObjC.Object(args[2]);
                var clsName = presentedVC.$className;
                if (clsName === "UIAlertController") {
                    var title = "";
                    try { title = presentedVC.title() ? presentedVC.title().toString() : ""; } catch(e) {}
                    console.log("[*] Presenting UIAlertController: " + title);
                    // Block presentation of any UIAlertController
                    if (title && (title.indexOf("\u5fc3\u60a6") !== -1 || title.indexOf("\u9a8c\u8bc1") !== -1 ||
                        title.indexOf("\u6fc0\u6d3b") !== -1 || title.indexOf("\u5361\u5bc6") !== -1 ||
                        title.indexOf("\u5931\u8d25") !== -1 || title.indexOf("\u4e0d\u5b58\u5728") !== -1 ||
                        title.indexOf("\u8f93\u5165") !== -1)) {
                        console.log("[*] BLOCKING presentation of: " + title);
                        // Replace the completion handler with a dismiss
                        args[4] = ptr(NULL);
                    }
                }
            }
        });
        console.log("[+] presentViewController hook installed");
    }

    // Hook viewDidAppear to auto-dismiss
    if (uiViewController && uiViewController["- viewDidAppear:"]) {
        Interceptor.attach(uiViewController["- viewDidAppear:"].implementation, {
            onEnter: function(args) {
                var self = new ObjC.Object(args[0]);
                var clsName = self.$className;
                if (clsName === "UIAlertController") {
                    var title = "";
                    try { title = self.title() ? self.title().toString() : ""; } catch(e) {}
                    console.log("[*] UIAlertController viewDidAppear: " + title);
                    if (title && (title.indexOf("\u5fc3\u60a6") !== -1 || title.indexOf("\u9a8c\u8bc1") !== -1 ||
                        title.indexOf("\u6fc0\u6d3b") !== -1 || title.indexOf("\u5361\u5bc6") !== -1 ||
                        title.indexOf("\u5931\u8d25") !== -1 || title.indexOf("\u4e0d\u5b58\u5728") !== -1 ||
                        title.indexOf("\u8f93\u5165") !== -1)) {
                        console.log("[*] Auto-dismissing: " + title);
                        // Use dispatch_async to dismiss on main queue
                        var dispatch_async = new NativeFunction(
                            Module.getGlobalExportByName('dispatch_async'),
                            'void', ['pointer', 'pointer']
                        );
                        var dispatch_get_main_queue = new NativeFunction(
                            Module.getGlobalExportByName('dispatch_get_main_queue'),
                            'pointer', []
                        );
                        var block = new ObjC.Block({
                            rettype: 'void',
                            argtypes: [],
                            implementation: function() {
                                self.dismissViewControllerAnimated_completion_(true, NULL);
                            }
                        });
                        dispatch_async(dispatch_get_main_queue(), block);
                    }
                }
            }
        });
        console.log("[+] viewDidAppear hook for auto-dismiss");
    }

    // Also hook UIAlertController.title setter to catch title being set
    var alertControllerCls = ObjC.classes.UIAlertController;
    if (alertControllerCls && alertControllerCls["- initWithTitle:message:preferredStyle:"]) {
        Interceptor.attach(alertControllerCls["- initWithTitle:message:preferredStyle:"].implementation, {
            onEnter: function(args) {
                var title = "";
                try { title = new ObjC.Object(args[2]).toString(); } catch(e) {}
                var message = "";
                try { message = new ObjC.Object(args[3]).toString(); } catch(e) {}
                console.log("[ALERT] initWithTitle: " + title + " message: " + message);
            }
        });
        console.log("[+] UIAlertController init hook installed");
    }
}

console.log("\n=== All hooks v6 installed ===\n");
