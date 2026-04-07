import 'dart:convert';

import 'package:lemon_tls/tls_socket.dart';

// Example: TLS server over TCP
// var server = net.createServer(function(tcp){

//   var socket = new tls.TLSSocket(tcp, {
//     isServer: true,
//     minVersion: 'TLSv1.2',
//     maxVersion: 'TLSv1.3',
//     ALPNProtocols: ['http/1.1'],
//     SNICallback: function (servername, cb) {
//       console.log('get cert for: '+servername);
//       cb(null, tls.createSecureContext({
//         key: fs.readFileSync('YOUR_CERT_PEM_FILE_PATH'),
//         cert: fs.readFileSync('YOUR_KEY_PEM_FILE_PATH')
//       }));
//     }
//   });

//   socket.on('secureConnect', function(){
//     console.log('[SRV] secure handshake established');

//     socket.write(new TextEncoder().encode('hi'));
//   });

//   socket.on('data', function(c){
//     // echo
//     socket.write(c);
//   });

//   socket.on('error', function(e){ console.error('[SRV TLS ERROR]', e); });
//   socket.on('close', function(){ console.log('[SRV] closed'); });
// });

// server.listen(8443, function(){ console.log('[SRV] listening 8443'); });
void main() async {
  TLSSocket socket = await TLSSocket.tlsSocket(
    'tcp',
    TlsOptions(
      isServer: true,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.3',
      ALPNProtocols: ['http/1.1'],
      SNICallback: (servername, cb) {
        print('get cert for: $servername');
        //   cb(null, tls.createSecureContext({
        //     key: fs.readFileSync('YOUR_CERT_PEM_FILE_PATH'),
        //     cert: fs.readFileSync('YOUR_KEY_PEM_FILE_PATH')
        //   }));
      },
    ),
  );

  socket.on('secureConnect', (_) {
    print('[SRV] secure handshake established');

    socket.write(utf8.encode('hi'));
  });

  socket.on('data', (c) {
    // echo
    print("Date received: $c");
    // socket.write(c);
  });

  socket.on('error', (e) {
    print('[SRV TLS ERROR]$e');
  });
  socket.on('close', (_) {
    print('[SRV] closed');
  });

  // await socket.connect();
}
