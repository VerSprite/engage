/**
 * 
 *  Simple ELF parser powered by Frida 
 *  ----------------------------------
 *  
 *  Written by : @rotlogix
 * 
 */


/**
 * @param {*} lib, symName
 */
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
 * @param {*} fd 
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
      var size = Memory.readS32(statBuff.add(0x30))
    if(size > 0) {
        console.log('[+] size of fd --> ' + size.toString());
        return size;
    } else {
        return 0;
    }
}

/**
 * 
 * @param {*} library_path 
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
    var rawElf = Memory.alloc(size);
    if(read(fd, rawElf, size) < 0) {
        console.log('[+] Unable to read ELF [!]');
        return -1;
    }
    console.log('[+] read --> ' + size + ' bytes [!]');
    console.log(hexdump(rawElf, {
        offset: 0,
        length: 20,
        header: true,
        ansi: true
      }));
    return rawElf
}

/**
 * 
 * @param {*} rawElf 
 */
function processELFHeader32(rawElf){
    var buffer = Memory.readByteArray(rawElf, 0x34);
    var elfHeaderDataView = new DataView(buffer);
    var e_type = elfHeaderDataView.getInt32(0x10, true);
    var e_machine = elfHeaderDataView.getInt16(0x12, true);
    var e_version = elfHeaderDataView.getUint32(0x14, true);
    var e_entry = elfHeaderDataView.getInt32(0x18, true);
    var e_phoff = elfHeaderDataView.getInt32(0x1C, true);
    var e_shoff = elfHeaderDataView.getInt32(0x20, true);
    var e_flags = elfHeaderDataView.getInt32(0x24, true);
    var e_ehsize = elfHeaderDataView.getInt16(0x28, true);
    var e_phentsize = elfHeaderDataView.getInt16(0x2A, true);
    var e_phnum = elfHeaderDataView.getInt16(0x2C, true);
    var e_shentsize = elfHeaderDataView.getInt16(0x2E, true);
    var e_shnum = elfHeaderDataView.getInt16(0x30, true);
    var e_shtrndx = elfHeaderDataView.getInt16(0x32, true);
    console.log('\n[+] HEADERS -----------------------------')
    console.log('[+] e_type      --> ' + e_type.toString());
    console.log('[+] e_machine   --> ' + e_machine.toString());
    console.log('[+] e_version   --> ' + e_version.toString());
    console.log('[+] e_entry     --> ' + e_entry.toString());
    console.log('[+] e_phoff     --> ' + e_phoff.toString());
    console.log('[+] e_shoff     --> 0x' + e_shoff.toString(16));
    console.log('[+] e_flags     --> 0x' + e_flags.toString(16));
    console.log('[+] e_ehsize    --> ' + e_ehsize.toString());
    console.log('[+] e_phentsize --> ' + e_phentsize.toString());
    console.log('[+] e_phnum     --> ' + e_phnum.toString());
    console.log('[+] e_shentsize --> ' + e_shentsize.toString());
    console.log('[+] e_shnum     --> ' + e_shnum.toString());
    console.log('[+] e_shtrndx   --> ' + e_shtrndx .toString());
    // Return elf header data
    return [e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum];
}

/**
 * 
 * @param {*} rawElf 
 * @param {*} sectionOffset 
 */
function getShstrtab32(rawElf, sectionOffset) {
    var buffer = Memory.readByteArray(rawElf, 0x34);
    var elfHeaderDataView = new DataView(buffer);
    var shstrtabIndex = elfHeaderDataView.getInt16(50, true);
    shstrtabHeaderOffset = sectionOffset + shstrtabIndex * 40;
    var shstrtabHeaderBuffer = Memory.readByteArray(rawElf.add(shstrtabHeaderOffset), 40);
    var shstrtabHeaderDataView = new DataView(shstrtabHeaderBuffer);
    var shstrtabDataOffset = shstrtabHeaderDataView.getInt32(16, true);
    var shstrtabDataSize = shstrtabHeaderDataView.getInt32(20, true);
    return shstrtabDataOffset;
}


/**
 * [e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum]
 */
function processProgramHeaders32(rawElf, elfHeader) {
    console.log('\n[+] SEGMENTS -----------------------------')
    var programHeaderIndex = 0;
    for(var i = 0 ; i < elfHeader[3] ; programHeaderIndex += elfHeader[2]) {
        var index = elfHeader[0] + programHeaderIndex;
        var buffer = Memory.readByteArray(rawElf.add(index), elfHeader[2]);
        var programHeaderView = new DataView(buffer);
        var p_type = programHeaderView.getInt32(0, true);
        switch(p_type) {
            case 6: // PT_PHDR
                console.log('[+] segment --> 0x' + index.toString(16) + ' : PT_PHDR');
                break;
            case 1: // PT_LOAD
                console.log('[+] segment --> 0x' + index.toString(16) + ' : PT_LOAD');
                break;
            case 2: // PT_DYNAMIC
                console.log('[+] segment --> 0x' + index.toString(16) + ' : PT_DYNAMIC');
                break;
            case 4: // PT_NOTE
                console.log('[+] segment --> 0x' + index.toString(16) + ' : PT_NOTE ');
                break;
        }
        i++;
    }
}

/**
 * [e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum]
 */
function processSectionHeaders32(rawElf, elfHeader) {
    console.log('\n[+] SECTIONS -----------------------------')
    var shstrtabDataOffset = getShstrtab32(rawElf, elfHeader[1]);
    var sectionIndex = 0;
    // for i is less than the number of sections += size of each section
    for(var i = 0; i < elfHeader[5] ; sectionIndex += 40) {
        // Calculate the offset into the section table
        var index = elfHeader[1] + sectionIndex;
        // Read in a section at the offset into the section table
        var buffer = Memory.readByteArray(rawElf.add(index), elfHeader[4]);
        var sectionDataView = new DataView(buffer);
        var shstrabOffset = sectionDataView.getInt32(0, true);
        var sectionName = Memory.readUtf8String(rawElf.add(shstrtabDataOffset + shstrabOffset));
        var s_addr = sectionDataView.getInt32(12, true);
        var s_offset = sectionDataView.getInt32(16, true);
        var s_size = sectionDataView.getInt32(20, true);
        if(sectionName) {
            console.log('[+] ' + sectionName + ' : 0x' + index.toString(16));
            console.log('[+] \ts_addr   --> 0x' + s_addr.toString(16) );
            console.log('[+] \ts_offset --> 0x' + s_offset.toString(16) );
            console.log('[+] \ts_size   --> 0x' + s_size.toString(16) );
        }
        i++;
    }
}

/**
 * 
 * @param {*} elf_path 
 */
function elfParser32(elf_path) {
    console.log('[+] Running elf parser [!]');
    var rawElf = openAndReadLibrary(elf_path);
    var elfHeader = processELFHeader32(rawElf);
    processProgramHeaders32(rawElf, elfHeader);
    processSectionHeaders32(rawElf, elfHeader);
}

// Do It
elfParser32('/data/data/com.versprite.poc/lib/libnative-lib.so');