/** Example
 *  -------
var impl = Memory.alloc(Process.pageSize);

Memory.patchCode(impl, Process.pageSize, function (code) {
  var cw = new X86Writer(code, { pc: impl });

  var libcPuts = Module.findExportByName(null, 'puts');
  var rl = new X86Relocator(libcPuts, cw);

  while (rl.readOne() !== 0) {
    console.log('Relocating: ' + rl.input.toString());
    rl.writeOne();
  }

  cw.flush();
});

var puts = new NativeFunction(impl, 'int', ['pointer']);
puts(Memory.allocUtf8String('Hello!'));
 */


/** Symbol Finder */
function getSymbolAddress(lib, symName) {
    var sym = Module.findExportByName(lib, symName);
    if(sym) {
        return sym;
    } else {
        return NaN;
    }
}

/**  
 * 
 * Find the target function address
 * ---------------------------------
**/
function getTargetFuncAddress() {
    var modules = Process.enumerateModulesSync()
    for(m in modules) {
        if(modules[m].name) {
            if(modules[m].name == 'libnative-lib.so') {
                console.log('[+] Found --> libnative-lib.so [!]');
                return getSymbolAddress('libnative-lib.so', 'Java_com_versprite_poc_Receiver_nativeFunc');
            }
        }
    }
}


/** Get the size of a file
 *  -----------------------
 *  http://codewiki.wikidot.com/c:system-calls:fstat
 */
function getFileSize(fd) {
    // TODO Get the actual size of this structure 
    var statBuff = Memory.alloc(500);
    console.log('[+] struct stat --> ' + statBuff.toString());
    var fstatSymbol = getSymbolAddress('libc.so', 'fstat');
    console.log('[+] fstat --> ' + fstatSymbol);
    var fstat  = new NativeFunction(fstatSymbol, 'int', ['int', 'pointer']);
    console.log('[+] Calling fstat() [!]');
    if(fd > 0) {
        var ret = fstat(fd, statBuff);
        if(ret < 0) {
            console.log('[+] fstat --> failed [!]');
        }
    }
    console.log(hexdump(statBuff, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
      }));
    var size = Memory.readU32(statBuff.add(48))
    if(size > 0) {
        console.log('[+] size of fd --> ' + size.toString());
        return size;
    } else {
        return 0;
    }
}

function handleElf(dv) {
    dataView = dv;
}


/** Open a read from a shared-library and return a DataView
 *  -------------------------------------------------------
 */
function openAndReadLibrary(library_path) {
    library_path_ptr = Memory.allocUtf8String(library_path);
    console.log('[+] path --> ' + library_path_ptr.toString());
    open = getSymbolAddress('libc.so', 'open');
    console.log('[+] open --> ' + open.toString());
    mOpen = new NativeFunction(open, 'int', ['pointer', 'int']);
    console.log('[+] Opening --> ' + library_path);
    var fd = mOpen(library_path_ptr, 0);
    if(fd < 0) {
        console.log('[+] Failed to open --> ' + library_path);
    }
    console.log('[+] fd --> ' + fd.toString());
    var size = getFileSize(fd);
    var read_sym = getSymbolAddress('libc.so', 'read');
    var read = new NativeFunction(read_sym, 'int', ['int', 'pointer', 'long']);
    var elfData = Memory.alloc(size);
    var ret = read(fd, elfData, size);
    if(ret < 0) {
        console.log('[+] read --> failed [!]');
    }
    console.log('[+] read --> ' + size + ' bytes [!]');
    console.log(hexdump(elfData, {
        offset: 0,
        length: 20,
        header: true,
        ansi: true
      }));
    var buffer = Memory.readByteArray(elfData, size);
    var dataView = new DataView(buffer);
    return dataView;
}

/** Load the hook library into the process
 *  --------------------------------------
 */
function loadHookLibrary(library_path) {
    library_path_ptr = Memory.allocUtf8String(library_path);
    var dlopen_sym = getSymbolAddress('libc.so', 'dlopen');
    console.log('[+] dlopen --> ' + dlopen_sym.toString());
    var dlopen = new NativeFunction(dlopen_sym, 'pointer', ['pointer', 'int'])
    console.log('[+] Loading --> libhook.so [!]');
    dlopen(library_path_ptr, 2);
    var modules = Process.enumerateModulesSync()
    for(m in modules) {
        if(modules[m].name == "libhook.so") {
            console.log('[+] libhook.so loaded [!]');
            var hookFunc = getSymbolAddress('libhook.so', '_Z8hookFuncv');
            if(hookFunc) {
                console.log('[+] hookFunc --> ' + hookFunc.toString());
                return hookFunc;
            }
        }
    }
}

// Globals
var nativeFunc = getTargetFuncAddress();
console.log('[+] Java_com_versprite_poc_Receiver_nativeFunc --> ' + nativeFunc.toString());
var dlopen = getSymbolAddress('libc.so', 'dlopen')
console.log('[+] dlopen --> ' + dlopen.toString());
var elfDataView = openAndReadLibrary('/data/data/com.versprite.poc/lib/libnative-lib.so');
console.log('[+] Signature --> ' + elfDataView.getInt8(1).toString(16), elfDataView.getInt8(2).toString(16), elfDataView.getInt8(3).toString(16));
loadHookLibrary('/data/local/tmp/libhook.so');