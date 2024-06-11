function resolveAddress(baseAddr, addr) {
    const idaBase = 0x180000000; // Enter the base address of jvm.dll as seen in your favorite disassembler (here IDA)
    const offset = ptr(addr).sub(idaBase); // Calculate offset in memory from base address in IDA database
    const result = ptr(baseAddr).add(offset); // Add current memory base address to offset of function to monitor
    console.log('[+] New addr=' + result); // Write location of function in memory to console
    return result;
}

function reverseAddress(baseAddr, addr) {
    const idaBase = 0x180000000; // Enter the base address of jvm.dll as seen in your favorite disassembler (here IDA)
    const offset = ptr(addr).sub(ptr(baseAddr)); // Add current memory base address to offset of function to monitor
    const result = ptr(idaBase).add(offset); // Calculate offset in memory from base address in IDA database
    console.log('[+] Reverse addr=' + result); // Write location of function in memory to console
    return result;
}

function PrintLog(log) {
    send(JSON.stringify(log))
}

async function main() {
    var baseAddr;
    while (true) {
        baseAddr = Module.findBaseAddress('wrapper.node');
        if (baseAddr != null) break;
    }
    console.log('[+] wrapper.node baseAddr: ' + baseAddr);

    const log1 = []; // Here we use the function address as seen in our disassembler
    for (var i = 0; i < log1.length; i++) {
        Interceptor.attach(resolveAddress(baseAddr, log1[i]), {
            // When function is called, print out its parameters
            onEnter(args) {
                var log = Memory.readCString(args[4].readPointer())
                if (log.search('{}') != -1)
                    log.replace('{}', Memory.readCString(args[5]));
                console.log('[+] log1 Arg: type=' + args[0] + ',file=' + Memory.readCString(args[1]) + ',line=' + args[2] + ',subtype=' + Memory.readCString(args[3]) + ',info=' + log);
                // console.log('[+] Caller ' + this.returnAddress + ' ' + reverseAddress(baseAddr, this.returnAddress));
            },
        });
    }

    const log2 = []; // Here we use the function address as seen in our disassembler
    for (var i = 0; i < log2.length; i++) {
        Interceptor.attach(resolveAddress(baseAddr, log2[i]), {
            // When function is called, print out its parameters
            onEnter(args) {
                var log = Memory.readCString(args[5].readPointer())
                var i = 5;
                while (log.search('{}') != -1) {
                    log = log.replace('{}', Memory.readCString(args[++i]));
                }
                console.log('[+] log2 Arg: from=' + Memory.readCString(args[0]) + ' type=' + args[1] + ',file=' + Memory.readCString(args[2]) + ',line=' + args[3] + ',subtype=' + Memory.readCString(args[4]) + ',info=' + log);
                // console.log('[+] Caller ' + this.returnAddress + ' ' + reverseAddress(baseAddr, this.returnAddress));
            },
        });
    }


    // const log3 = [0x1805BCF10]; // Here we use the function address as seen in our disassembler
    // for (var i = 0; i < log3.length; i++) {
    //     Interceptor.attach(resolveAddress(baseAddr, log3[i]), {
    //         // When function is called, print out its parameters
    //         onEnter(args) {
    //             console.log('[+] printf Arg: a1=' + args[0] + ',format=' + Memory.readCString(args[1].readPointer()) + ',a3=' + Memory.readCString(args[2].readPointer()) + ',a4=' + Memory.readCString(args[3].readPointer()));
    //             // console.log('[+] Caller ' + this.returnAddress + ' ' + reverseAddress(baseAddr, this.returnAddress));
    //         },
    //     });
    // }

    // const log4 = [0x18000AAB0]; // Here we use the function address as seen in our disassembler
    // for (var i = 0; i < log4.length; i++) {
    //     Interceptor.attach(resolveAddress(baseAddr, log4[i]), {
    //         // When function is called, print out its parameters
    //         onEnter(args) {
    //             var log = Memory.readCString(args[2])
    //             var i = 4;
    //             var a;
    //             console.log('LOG: ' + log)
    //             while ((a = log.search('%')) != -1) {
    //                 switch (log[a + 1]) {
    //                     case 's':
    //                         log = log.replace('%s', Memory.readCString(args[++i]));
    //                         break;
    //                     case 'd':
    //                         log = log.replace('%d', args[++i]);
    //                         break;
    //                     case 'u':
    //                         log = log.replace('%u', args[++i]);
    //                         break;
    //                     case 'l':
    //                         switch (log[a + 2]) {
    //                             case 'd':
    //                                 log = log.replace('%ld', args[++i]);
    //                                 break;
    //                             case 'u':
    //                                 log = log.replace('%lu', args[++i]);
    //                                 break;
    //                             default:
    //                                 break;
    //                         }
    //                     default:
    //                         break;
    //                 }
    //             }
    //             // console.log('[+] log2 Arg: from=' + Memory.readCString(args[0]) + ' type=' + args[1] + ',file=' + Memory.readCString(args[2]) + ',line=' + args[3] + ',info=' + log);
    //             // console.log('[+] Caller ' + this.returnAddress + ' ' + reverseAddress(baseAddr, this.returnAddress));
    //             console.log('[+] log4 Arg: file=' + Memory.readCString(args[0]) + ',line=' + args[1] + ',log=' + log + ',type=' + Memory.readCString(args[3]) + ',a5=' + args[4])
    //         },
    //     });
    // }

    // Interceptor.attach(resolveAddress(baseAddr, 0x18305F530), {
    //     // When function is called, print out its parameters
    //     onEnter(args) {
    //         console.log('[+] DidRecvResponseData Arg: a1=' + args[0]);
    //         console.log(Memory.readByteArray((args[1].readPointer()).readPointer(), 0x100));
    //         // console.log('[+] Caller ' + this.returnAddress + ' ' + reverseAddress(baseAddr, this.returnAddress));
    //     },
    // });

    // Interceptor.attach(resolveAddress(baseAddr, 0x18002EB50), {
    //     // When function is called, print out its parameters
    //     onEnter(args) {
    //         console.log('[+] SIGN Arg: from=' + Memory.readCString(args[0]) + ' type=' + Memory.readCString(args[1]) + ',file=' + args[2] + ',line=' + args[3] + ',subtype=' + Memory.readCString(args[4]));
    //         // console.log('[+] Caller ' + this.returnAddress + ' ' + reverseAddress(baseAddr, this.returnAddress));
    //     },
    // });

    function bytesToHex(arrayBuffer) {
        var bytes = new Uint8Array(arrayBuffer)
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push((bytes[i] >>> 4).toString(16));
            hex.push((bytes[i] & 0xF).toString(16));
        }
        return hex.join("");
    }

    // ecc公钥导出
    // Interceptor.attach(wrapper.add(0x1FACE50), {
    //     onEnter: function (args) {
    //         this.outPublic = args[1]
    //         this.outPublicLength = args[2]
    //     },
    //     onLeave: function(retval) {
    //         var pubKey = null
    //         if (this.outPublicLength.toInt32() > retval.toInt32()) {
    //             var pubKey = this.outPublic.readByteArray(retval.toInt32())
    //         } else {
    //             var pubKey = this.outPublic.readByteArray(this.outPublicLength.toInt32())
    //         }
    //         PrintLog({"publicKey": bytesToHex(pubKey)})
    //     }
    // })

    // ecdh密钥协商
    // Interceptor.attach(wrapper.add(0x1FBD820), {
    //     onEnter: function (args) {
    //         this.outShare = args[0]
    //     },
    //     onLeave: function(retval) {
    //         var shaKey = this.outShare.readByteArray(retval.toInt32())
    //         PrintLog({"shareKey": bytesToHex(shaKey)})
    //     }
    // })
    const readVector = (x) => x.readPointer().readByteArray(+x.add(8).readPointer().sub(x.readPointer()));
    // AES加密算法
    Interceptor.attach(resolveAddress(baseAddr, 0x1806AB91E), {
        onEnter: function (args) {
            //console.log("AES_encrypt START======================")
            this.data = readVector(args[0])
            this.key = readVector(args[1])
            this.iv = readVector(args[2])
            this.tag = args[3]
            this.result = args[4]
            //console.log("AES_encrypt => size:", dataSize, "key:", bytesToHex(key), "iv:", bytesToHex(iv), "data:", bytesToHex(data))

        },
        onLeave: function () {
            var resultSize = this.result.add(0x4).readPointer().sub(this.result.readPointer())
            // console.log("tag", bytesToHex(this.out1.readPointer().readByteArray(0x10)))
            // console.log("data", bytesToHex(this.out2.readPointer().readByteArray(resultSize.toInt32())))
            // console.log("AES_encrypt END========================")
            PrintLog({
                "type": "aes_encrypt",
                "data": bytesToHex(this.data),
                "key": bytesToHex(this.key),
                "iv": bytesToHex(this.iv),
                "result": bytesToHex(readVector(this.result)),
                "tag": bytesToHex(readVector(this.tag))
            })
        }
    })

    // AES解密算法
    Interceptor.attach(resolveAddress(baseAddr, 0x1806ABE6E), {
        onEnter: function (args) {
            //console.log("AES_decrypt START======================")
            this.data = readVector(args[0])
            this.key = readVector(args[1])
            this.iv = readVector(args[2])
            this.tag = readVector(args[3])
            this.result = args[4]
            // console.log("AES_decrypt => size:", dataSize, "key:", bytesToHex(key), "iv:", bytesToHex(iv), "data:", bytesToHex(data))
        },
        onLeave: function () {
            // console.log("tag", bytesToHex(this.out1.readPointer().readByteArray(0x10)))
            // console.log("data", bytesToHex(this.out2.readPointer().readByteArray(resultSize.toInt32())))
            // console.log("AES_decrypt END========================")
            PrintLog({
                "type": "aes_decrypt",
                "data": bytesToHex(this.data),
                "tag": bytesToHex(this.tag),
                "key": bytesToHex(this.key),
                "iv": bytesToHex(this.iv),
                "result": bytesToHex(readVector(this.result)),
            })
        }
    })


    // TEA加密
    Interceptor.attach(resolveAddress(baseAddr, 0x1823CFCF5), {
        onEnter: function (args) {
            this.data = args[0].readByteArray(args[1].toInt32())
            this.key = args[2].readByteArray(args[3].toInt32())
            this.out = args[4]
            this.out_len = args[5]
            //PrintLog({"key":"encode","size:": this.context.edx, "key:": bytesToHex(key), "data:": bytesToHex(data)})
        },
        onLeave: function () {
            PrintLog({
                "type": "tea_encrypt",
                "data": bytesToHex(this.data),
                "key": bytesToHex(this.key),
                "result": bytesToHex(this.out.readByteArray(this.out_len.readPointer().toInt32()))
            })
        }
    })
    // TEA解密
    Interceptor.attach(resolveAddress(baseAddr, 0x1823CFF61), {
        onEnter: function (args) {
            this.data = args[0].readByteArray(args[1].toInt32())
            this.key = args[2].readByteArray(args[3].toInt32())
            this.out = args[4]
            this.out_len = args[5]
            //PrintLog({"key":"encode","size:": this.context.edx, "key:": bytesToHex(key), "data:": bytesToHex(data)})
        },
        onLeave: function () {
            PrintLog({
                "type": "tea_decrypt",
                "data": bytesToHex(this.data),
                "key": bytesToHex(this.key),
                "result": bytesToHex(this.out.readByteArray(this.out_len.readPointer().toInt32()))
            })
        }
    })

    // TEA加密 ?
    // teaEncrypt = [0x1830762BE, 0x180b416ab]
    // for (var i = 0; i < teaEncrypt.length; i++) {
    //     Interceptor.attach(resolveAddress(baseAddr, teaEncrypt[i]), {
    //         onEnter: function (args) {
    //             this.data = args[0].readByteArray(args[1].toInt32())
    //             this.key = args[2].readByteArray(0x10)
    //             this.out = args[3]
    //             this.out_len = args[4]
    //             //PrintLog({"key":"encode","size:": this.context.edx, "key:": bytesToHex(key), "data:": bytesToHex(data)})
    //         },
    //         onLeave: function () {
    //             PrintLog({
    //                 "type": "encrypt",
    //                 "data": bytesToHex(this.data),
    //                 "key": bytesToHex(this.key),
    //                 "result": bytesToHex(this.out.readByteArray(this.out_len.readPointer().toInt32()))
    //             })
    //         }
    //     })
    // }
    // TEA解密 ?
    // Interceptor.attach(resolveAddress(baseAddr, 0x182139340), {
    //     onEnter: function (args) {
    //         PrintLog({
    //             "type": "info",
    //             "data": {
    //                 "from": "0x182139340",
    //                 "arg0": args[0],
    //                 "arg1": args[1],
    //                 "arg2": args[2],
    //                 "arg3": args[3],
    //             },
    //         })
    //         this.data = args[0].readByteArray(args[1].toInt32())
    //         this.key = args[2].readByteArray(0x10)
    //         this.out_len = args[3]
    //         //PrintLog({"key":"decode","size:": this.context.edx, "key:": bytesToHex(key), "data:": bytesToHex(data)})
    //     },
    //     onLeave: function (ret) {
    //         PrintLog({
    //             "type": "decrypt",
    //             "data": bytesToHex(this.data),
    //             "key": bytesToHex(this.key),
    //             // "result": bytesToHex(ret.readByteArray(this.out_len.readPointer().toInt32()))
    //         })
    //     }
    // })

}

main();
