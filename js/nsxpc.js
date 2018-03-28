var protocol_getName = Module.findExportByName("/usr/lib/libobjc.A.dylib", "protocol_getName");
// const char * protocol_getName(Protocol *proto);
var my_protocol_getName = new NativeFunction(protocol_getName, 'pointer', ['pointer']);
var shouldAcceptNewConnection = ObjC.classes.CMLipoServiceDelegate["- listener:shouldAcceptNewConnection:"];
var interfaceWithProtocol = ObjC.classes.NSXPCInterface["+ interfaceWithProtocol:"];
var obtainArchitecturesForBinaryWithReply = ObjC.classes.CMLipoTask["- obtainArchitecturesForBinary:withReply:"];

Interceptor.attach(shouldAcceptNewConnection.implementation, {
  onEnter: function(args) {
    console.log("[+] Hooked shouldAcceptNewConnection [!]");
    console.log("[+] NSXPCConnection => " + args[2]);

  }
});

Interceptor.attach(interfaceWithProtocol.implementation, {
    onEnter: function(args) {
      console.log("[+] Hooked interfaceWithProtocol [!]");
      console.log("[+] Protocol => " + args[2]);
      // Returns a const char *
      var name = my_protocol_getName(args[2]);
      console.log("[+] Protocol Name => " + Memory.readUtf8String(name));
    }
  });

  Interceptor.attach(obtainArchitecturesForBinaryWithReply.implementation, {
    onEnter: function(args) {
      console.log("[+] Hooked obtainArchitecturesForBinaryWithReply [!]");
      console.log("[+] Binary => " + ObjC.Object(args[2]).toString());
    }
  });
