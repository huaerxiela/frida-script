
let target_code_hex;
let call_number_openat;
let call_number_faccessat;
let arch = Process.arch;
if ("arm" === arch){
    target_code_hex = "00 00 00 EF";
    call_number_openat = 322;
    call_number_faccessat = 334;
}else if("arm64" === arch){
    target_code_hex = "01 00 00 D4";
    call_number_openat = 56;
    call_number_faccessat = 48;
}else {
    console.log("arch not support!")
}

if (arch){
    console.log("\nthe_arch = " + arch);
    // 直接Process.enumerateModules()，可能会因为某些地址不可读造成非法访问
    Process.enumerateRanges('r--').forEach(function (range) {
        if(!range.file || !range.file.path){
            return;
        }
        let path = range.file.path;
        if ((!path.startsWith("/data/app/")) || (!path.endsWith(".so"))){
            return;
        }
        let baseAddress = Module.getBaseAddress(path);
        console.log("\npath = " + path + " , baseAddress = " + baseAddress + " , rangeAddress = " + range.base + " , size = " + range.size);

        Memory.scan(range.base, range.size, target_code_hex, {
            onMatch: function (match){
                let code_address = match;
                let code_address_str = code_address.toString();
                if (code_address_str.endsWith("0") || code_address_str.endsWith("4") || code_address_str.endsWith("8") || code_address_str.endsWith("c")){
                    console.log("--------------------------");
                    let call_number = 0;
                    if ("arm" === arch){
                        // call_number = (code_address.sub(0x4).readS16() - 28672);  // 0x7000
                        call_number = (code_address.sub(0x4).readS32()) & 0xFFF;
                    }else if("arm64" === arch){
                        call_number = (code_address.sub(0x4).readS32() >> 5) & 0xFFFF;
                    }else {
                        console.log("the arch get call_number not support!")
                    }
                    console.log("find svc : address = " + code_address + " , call_number = " + call_number + " , offset = " + code_address.sub(baseAddress));

                    // hook svc __NR_openat
                    if (call_number_openat === call_number){
                        let target_hook_addr = code_address;
                        let target_hook_addr_offset = target_hook_addr.sub(baseAddress);
                        console.log("find svc openat , start inlinehook by frida!")
                        Interceptor.attach(target_hook_addr, {
                            onEnter: function (args){
                                console.log("\nonEnter_" + target_hook_addr_offset + " , __NR_openat , args[1] = " + args[1].readCString());
                                this.new_addr = Memory.allocUtf8String("/proc/self/status11");
                                args[1] = this.new_addr;
                                console.log("onEnter_" + target_hook_addr_offset + " , __NR_openat , args[1] = " + args[1].readCString());
                            }, onLeave: function (retval){
                                console.log("onLeave_" + target_hook_addr_offset + " , __NR_openat , retval = " + retval)
                            }
                        });

                    }
                    // hook svc __NR_faccessat
                    if (call_number_faccessat === call_number){
                        let target_hook_addr = code_address;
                        let target_hook_addr_offset = target_hook_addr.sub(baseAddress);
                        console.log("find svc faccessat , start inlinehook by frida!")
                        Interceptor.attach(target_hook_addr, {
                            onEnter: function (args){
                                console.log("\nonEnter_" + target_hook_addr_offset + " , __NR_faccessat , args[1] = " + args[1].readCString());
                                // this.new_addr = Memory.allocUtf8String("/proc/self/status11");
                                // args[1] = this.new_addr;
                                console.log("onEnter_" + target_hook_addr_offset + " , __NR_faccessat , args[1] = " + args[1].readCString());
                            }, onLeave: function (retval){
                                console.log("onLeave_" + target_hook_addr_offset + " , __NR_faccessat , retval = " + retval)
                            }
                        });

                    }
                }
            }, onComplete: function () {}
        });

    });
}


