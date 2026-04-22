










































Kelly Kinyama (TELA) (TCS)
Copilot Chat (Basic)


i am implementing quic.server: PS C:\www\node\quic

GPT 5.4 Think




You said:
bull's eye: server: PS C:\www\dart\lemon-tls> dart lib\quic\quic_learn\server\server2.dart
Private Key PEM:
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII7KT49E+nMaE7fkfsP/Qmy50QdW4H/PDUtn31yDak+foAoGCCqGSM49
AwEHoUQDQgAEGZc8vUE9TnozrqO9egmtFicMUrIi27qMpF4UZ+jHSd5/y56Hq1xU
eY7sTSvdVgDwYiBOxeO91vxK6J9hiUOV6Q==
-----END EC PRIVATE KEY-----

Public Key PEM:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGZc8vUE9TnozrqO9egmtFicMUrIi
27qMpF4UZ+jHSd5/y56Hq1xUeY7sTSvdVgDwYiBOxeO91vxK6J9hiUOV6Q==
-----END PUBLIC KEY-----

Padded X length: 32
Padded Y length: 32
Certificate PEM: -----BEGIN CERTIFICATE-----
MIIBGDCBvaADAgECAgEBMAwGCCqGSM49BAMCBQAwFDESMBAGA1UEAxMJbG9jYWxo
b3N0MB4XDTI2MDQyMjE1MDEyMFoXDTI2MDUwNTE1MDEyMFowFDESMBAGA1UEAxMJ
bG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGZc8vUE9TnozrqO9
egmtFicMUrIi27qMpF4UZ+jHSd5/y56Hq1xUeY7sTSvdVgDwYiBOxeO91vxK6J9h
iUOV6TAMBggqhkjOPQQDAgUAA0gAMEUCIQDkbKvIU+Cf4HZWaLMG1XYlFq0qWqQB
3mkU6ppEYAxq0QIgbsqxnFt7Y9MOb++dFdXf2vkhHPi2sZTq45hXnSgmNc8=
-----END CERTIFICATE-----
Fingerprint: 198E2DBA7096E7A172C3661DF5F7079F4227EF621D0BB7F28A063FC8696AB651
Fingerprint: 198E2DBA7096E7A172C3661DF5F7079F4227EF621D0BB7F28A063FC8696AB651
Certificate finger print: 19:8E:2D:BA:70:96:E7:A1:72:C3:66:1D:F5:F7:07:9F:42:27:EF:62:1D:0B:B7:F2:8A:06:3F:C8:69:6A:B6:51
Fingerprint: 90E346858394B41C7E24CC1F391664233329CC95CB3FD40D03A9DFB98DED00A4
Server certificate hash: 90:E3:46:85:83:94:B4:1C:7E:24:CC:1F:39:16:64:23:33:29:CC:95:CB:3F:D4:0D:03:A9:DF:B9:8D:ED:00:A4
server listening ip:127.0.0.1:4433
Data datagram received: 1200
2
📥 Server received packet level=EncryptionLevel.initial len=217
✅ Server Initial keys ready
  initialRead : QuicKeys{
  key: b14b918124fda5c8d79847602fa3520b;
  iv:  ddbc15dea80925a55686a7df;
  hp:  6df4e9d737cdf714711d7c617ee82981;
}
  initialWrite: QuicKeys{
  key: d77fc4056fcfa32bd1302469ee6ebf90;
  iv:  fcb748e37ff79860faa07477;
  hp:  440b2725e91dc79b370711ef792faa3d;
}
  clientOrigDcid: 0001020304050607
  peerScid      : 0d8e76ed0d673147
  localCid      : 97ec96c058e10ec6
--- decryptQuicPacket keys ---
READ.key = b14b918124fda5c8d79847602fa3520b
READ.iv  = ddbc15dea80925a55686a7df
READ.hp  = 6df4e9d737cdf714711d7c617ee82981
dcid     = 0001020304050607
pkt[0]   = 0xc8
pkt.len  = 217
Unmasked first byte: 0xc0
Packet number offset: 26
Packet number length: 1
Packet number: 0
Nonce: ddbc15dea80925a55686a7df
AAD (hex): c000000001080001020304050607080d8e76ed0d6731470040bf00
Ciphertext+Tag len: 190
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 060040aa010000a60303f5baa8c88cfa
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed CRYPTO frame offset=0 len=170
✅ Server has full ClientHello
✅ Client offered ALPNs: []
✅ Server selected ALPN: quic-echo-example
✅ Server handshake keys ready
  handshakeRead : QuicKeys{
  key: 0d30b3d784eac86f44e451d6818c6e16;
  iv:  2cea817819eccd5fcf0fc922;
  hp:  e7a7b5308ffdeae2b6e06963422499e0;
}
  handshakeWrite: QuicKeys{
  key: 331cf415374046f4f33c777d3132b795;
  iv:  f7670e097f13eb9fb2a92229;
  hp:  6cbc7bdb0e9b380bd59b1d4783d5cde6;
}
✅ Server handshake artifacts stored
  encryptedExtensions: 96 bytes
  certificate        : 297 bytes
  certificateVerify  : 79 bytes
✅ Server built Finished verify_data=4aa754582284624ea8adc8f9e317f5a4b770c875a13a99dfa02a210a43d65bf3
--- encryptQuicPacket keys ---
READ.key = d77fc4056fcfa32bd1302469ee6ebf90
READ.iv  = fcb748e37ff79860faa07477
READ.hp  = 440b2725e91dc79b370711ef792faa3d
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x06
pkt.len  = 94
✅ Server sent Initial(ServerHello) pn=0 dcid=0d8e76ed0d673147 scid=97ec96c058e10ec6       
--- encryptQuicPacket keys ---
READ.key = 331cf415374046f4f33c777d3132b795
READ.iv  = f7670e097f13eb9fb2a92229
READ.hp  = 6cbc7bdb0e9b380bd59b1d4783d5cde6
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x06
pkt.len  = 100
✅ Server sent Handshake pn=1 offset=0 len=96 dcid=0d8e76ed0d673147 scid=97ec96c058e10ec6  
--- encryptQuicPacket keys ---
READ.key = 331cf415374046f4f33c777d3132b795
READ.iv  = f7670e097f13eb9fb2a92229
READ.hp  = 6cbc7bdb0e9b380bd59b1d4783d5cde6
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x06
pkt.len  = 302
✅ Server sent Handshake pn=2 offset=96 len=297 dcid=0d8e76ed0d673147 scid=97ec96c058e10ec6
--- encryptQuicPacket keys ---
READ.key = 331cf415374046f4f33c777d3132b795
READ.iv  = f7670e097f13eb9fb2a92229
READ.hp  = 6cbc7bdb0e9b380bd59b1d4783d5cde6
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x06
pkt.len  = 84
✅ Server sent Handshake pn=3 offset=393 len=79 dcid=0d8e76ed0d673147 scid=97ec96c058e10ec6
--- encryptQuicPacket keys ---
READ.key = 331cf415374046f4f33c777d3132b795
READ.iv  = f7670e097f13eb9fb2a92229
READ.hp  = 6cbc7bdb0e9b380bd59b1d4783d5cde6
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x06
pkt.len  = 40
✅ Server sent Handshake pn=4 offset=472 len=36 dcid=0d8e76ed0d673147 scid=97ec96c058e10ec6
🎉 Server payload parsing complete.
--- encryptQuicPacket keys ---
READ.key = d77fc4056fcfa32bd1302469ee6ebf90
READ.iv  = fcb748e37ff79860faa07477
READ.hp  = 440b2725e91dc79b370711ef792faa3d
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x03
pkt.len  = 8
--- encryptQuicPacket keys ---
READ.key = d77fc4056fcfa32bd1302469ee6ebf90
READ.iv  = fcb748e37ff79860faa07477
READ.hp  = 440b2725e91dc79b370711ef792faa3d
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x03
pkt.len  = 1158
✅ Sent ACK (EncryptionLevel.initial) pn=1 acked=[0]
📥 Server received packet level=EncryptionLevel.application len=983
ℹ️ Ignoring early Application packet (1-RTT keys not ready)
Data datagram received: 1200
2
📥 Server received packet level=EncryptionLevel.initial len=50
--- decryptQuicPacket keys ---
READ.key = b14b918124fda5c8d79847602fa3520b
READ.iv  = ddbc15dea80925a55686a7df
READ.hp  = 6df4e9d737cdf714711d7c617ee82981
dcid     = 0001020304050607
pkt[0]   = 0xc0
pkt.len  = 50
Unmasked first byte: 0xc0
Packet number offset: 25
Packet number length: 1
Packet number: 1
Nonce: ddbc15dea80925a55686a7de
AAD (hex): c0000000010897ec96c058e10ec6080d8e76ed0d673147001901
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0300000000000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=0 delay=0 firstRange=0
🎉 Server payload parsing complete.
📥 Server received packet level=EncryptionLevel.application len=1150
ℹ️ Ignoring early Application packet (1-RTT keys not ready)
Data datagram received: 49
1
📥 Server received packet level=EncryptionLevel.handshake len=49
--- decryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xe6
pkt.len  = 49
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 0
Nonce: 2cea817819eccd5fcf0fc922
AAD (hex): e0000000010897ec96c058e10ec6080d8e76ed0d6731471900
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0301000000000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=1 delay=0 firstRange=0
🎉 Server payload parsing complete.
Data datagram received: 49
1
📥 Server received packet level=EncryptionLevel.handshake len=49
--- decryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xed
pkt.len  = 49
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 1
Nonce: 2cea817819eccd5fcf0fc923
AAD (hex): e0000000010897ec96c058e10ec6080d8e76ed0d6731471901
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0302000001000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=2 delay=0 firstRange=1
🎉 Server payload parsing complete.
Data datagram received: 49
1
📥 Server received packet level=EncryptionLevel.handshake len=49
--- decryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xe9
pkt.len  = 49
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 2
Nonce: 2cea817819eccd5fcf0fc920
AAD (hex): e0000000010897ec96c058e10ec6080d8e76ed0d6731471902
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0303000002000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=3 delay=0 firstRange=2
🎉 Server payload parsing complete.
Data datagram received: 49
1
📥 Server received packet level=EncryptionLevel.handshake len=49
--- decryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xe0
pkt.len  = 49
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 3
Nonce: 2cea817819eccd5fcf0fc921
AAD (hex): e0000000010897ec96c058e10ec6080d8e76ed0d6731471903
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0304000003000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=4 delay=0 firstRange=3
🎉 Server payload parsing complete.
Data datagram received: 80
1
📥 Server received packet level=EncryptionLevel.handshake len=80
--- decryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xeb
pkt.len  = 80
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 4
Nonce: 2cea817819eccd5fcf0fc926
AAD (hex): e0000000010897ec96c058e10ec6080d8e76ed0d6731473804
Ciphertext+Tag len: 55
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 060024140000202666557943e4d2d3d4
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed CRYPTO frame offset=0 len=36
✅ Server received Client Finished
  expected: 2666557943e4d2d3d4e0de303801574804507005c25a7a3839a5c08c043cd084
  actual  : 2666557943e4d2d3d4e0de303801574804507005c25a7a3839a5c08c043cd084
✅ Client Finished verified
✅ Server 1-RTT keys installed
  appRead : QuicKeys{
  key: efe4495b835eeb4b38da9bcae3ae905e;
  iv:  8e7f76f8b2fa8cf8a4c2dc24;
  hp:  114739bafdefc5213c8abf16c60af2d0;
}
  appWrite: QuicKeys{
  key: 60f9e0cc84dc83d1b043edead82d9351;
  iv:  6f1a6c77e628510f6dc45c8f;
  hp:  703ac09ad8f1be28ade28435fa546d36;
}
--- encryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x0a
pkt.len  = 19
✅ Sent application STREAM pn=0 streamId=3 len=16 fin=false
✅ HTTP/3 control stream sent
🎉 Server payload parsing complete.
Data datagram received: 75
1
📥 Server received packet level=EncryptionLevel.application len=75
--- decryptQuicPacket keys ---
READ.key = efe4495b835eeb4b38da9bcae3ae905e
READ.iv  = 8e7f76f8b2fa8cf8a4c2dc24
READ.hp  = 114739bafdefc5213c8abf16c60af2d0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x5d
pkt.len  = 75
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 0
Nonce: 8e7f76f8b2fa8cf8a4c2dc24
AAD (hex): 4097ec96c058e10ec600
Ciphertext+Tag len: 65
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0a002e012c0000cfd750096c6f63616c
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed STREAM streamId=0 offset=0 len=46 fin=false
✅ WebTransport session accepted on stream 0
--- encryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x0a
pkt.len  = 46
✅ Sent application STREAM pn=1 streamId=0 len=43 fin=false
🎉 Server payload parsing complete.
--- encryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.application) pn=2 acked=[0]
Data datagram received: 33
1
📥 Server received packet level=EncryptionLevel.application len=33
--- decryptQuicPacket keys ---
READ.key = efe4495b835eeb4b38da9bcae3ae905e
READ.iv  = 8e7f76f8b2fa8cf8a4c2dc24
READ.hp  = 114739bafdefc5213c8abf16c60af2d0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x52
pkt.len  = 33
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 1
Nonce: 8e7f76f8b2fa8cf8a4c2dc25
AAD (hex): 4097ec96c058e10ec601
Ciphertext+Tag len: 23
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 31050001020304
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed DATAGRAM len=5
📦 WebTransport datagram session=0 len=4
--- encryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x31
pkt.len  = 7
✅ Sent WebTransport DATAGRAM pn=3 session=0 len=4
🎉 Server payload parsing complete.
--- encryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 0d8e76ed0d673147
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.application) pn=4 acked=[0, 1]
client: PS C:\www\dart\lemon-tls> dart lib\quic\quic_learn\client\client3.dart
Client initial key: b14b918124fda5c8d79847602fa3520b
Client initial IV:  ddbc15dea80925a55686a7df
Server initial key: d77fc4056fcfa32bd1302469ee6ebf90
Server initial IV:  fcb748e37ff79860faa07477
Client initial header protection key: 6df4e9d737cdf714711d7c617ee82981
Server initial header protection key: 440b2725e91dc79b370711ef792faa3d
✅ QUIC initial secrets verified
listening ip:127.0.0.1:62209
🚨 Built dynamic ClientHello len=170
🚨 Dynamic ALPNs: []
--- encryptQuicPacket keys ---
READ.key = b14b918124fda5c8d79847602fa3520b
READ.iv  = ddbc15dea80925a55686a7df
READ.hp  = 6df4e9d737cdf714711d7c617ee82981
dcid     = 0001020304050607
pkt[0]   = 0x06
pkt.len  = 174
🚀 Sent Initial ClientHello pn=0 dcid=0001020304050607 scid=0d8e76ed0d673147 len=1200
Data datagram received: 137
1
✅ Learned server CID: 97ec96c058e10ec6
Encryption level: EncryptionLevel.initial
--- decryptQuicPacket keys ---
READ.key = d77fc4056fcfa32bd1302469ee6ebf90
READ.iv  = fcb748e37ff79860faa07477
READ.hp  = 440b2725e91dc79b370711ef792faa3d
dcid     = 0001020304050607
pkt[0]   = 0xc7
pkt.len  = 137
Unmasked first byte: 0xc0
Packet number offset: 26
Packet number length: 1
Packet number: 0
Nonce: fcb748e37ff79860faa07477
AAD (hex): c000000001080d8e76ed0d6731470897ec96c058e10ec600406f00
Ciphertext+Tag len: 110
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0600405a0200005603031e2a0e4a982c
--- encryptQuicPacket keys ---
READ.key = b14b918124fda5c8d79847602fa3520b
READ.iv  = ddbc15dea80925a55686a7df
READ.hp  = 6df4e9d737cdf714711d7c617ee82981
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.initial) pn=1 dcid=97ec96c058e10ec6 scid=0d8e76ed0d673147 acked=[0]
--- Parsing Decrypted QUIC Payload ---
✅ Parsed CRYPTO Frame: offset=0, length=90
handshake length: 86
✅ ServerHello received (86 bytes)

🎉 Payload parsing complete.
Server key_share pub (32 bytes): 6184637c503d7e93fab8339e7fada18642c5d4fb282839a02eedf72d51518e23
Hashing ClientHello + ServerHello: 010000a60303f5baa8c88cfa2fc670ee287483b56c601e8ac30539ea60019b89300dd9d2736b000006130113021303010000770000000e000c0000096c6f63616c686f7374000a00080006001d00170018000d0006000404030804003300260024001d002019f48cc743fd98eef57b57ca1138e0ebe92570f310948efddfda3b70c5eaad13002d00020101002b000302030400390014010275300404001000000f080d8e76ed0d6731470200005603031e2a0e4a982c8e86f57bb4d5e8f6034b69a877cde48c29ab63da1132fe74a9fa00130100002e002b0002030400330024001d00206184637c503d7e93fab8339e7fada18642c5d4fb282839a02eedf72d51518e23
helloHash: 1afbd27be8a13e2a3b4309b61859de125b2cab530b8f5a7893b38413ba467f1a
handshake read: QuicKeys{
  key: 331cf415374046f4f33c777d3132b795;
  iv:  f7670e097f13eb9fb2a92229;
  hp:  6cbc7bdb0e9b380bd59b1d4783d5cde6;
}
handshake write: QuicKeys{
  key: 0d30b3d784eac86f44e451d6818c6e16;
  iv:  2cea817819eccd5fcf0fc922;
  hp:  e7a7b5308ffdeae2b6e06963422499e0;
}
✅ QUIC/TLS handshake keys derived (spec-correct)
parsed: ParsedQuicPayload(frames=0, cryptoFrames=0, tlsMessages=1, ack=false)
Data datagram received: 142
1
Encryption level: EncryptionLevel.handshake
--- decryptQuicPacket keys ---
READ.key = 331cf415374046f4f33c777d3132b795
READ.iv  = f7670e097f13eb9fb2a92229
READ.hp  = 6cbc7bdb0e9b380bd59b1d4783d5cde6
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xee
pkt.len  = 142
Unmasked first byte: 0xe0
Packet number offset: 25
Packet number length: 1
Packet number: 1
Nonce: f7670e097f13eb9fb2a92228
AAD (hex): e000000001080d8e76ed0d6731470897ec96c058e10ec6407501
Ciphertext+Tag len: 116
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 060040600800005c005a001000140012
--- encryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.handshake) pn=0 dcid=97ec96c058e10ec6 scid=0d8e76ed0d673147 acked=[1]
--- Parsing Decrypted QUIC Payload ---
✅ Parsed CRYPTO Frame: offset=0, length=96
handshake length: 92
✅ EncryptedExtensions received (92 bytes)
ee: ✅ EncryptedExtensions([  - Ext: application_layer_protocol_negotiation, Length: 20,   - Ext: quic_transport_parameters, Length: 62] extensions)

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=0, cryptoFrames=0, tlsMessages=1, ack=false)
Data datagram received: 344
1
Encryption level: EncryptionLevel.handshake
--- decryptQuicPacket keys ---
READ.key = 331cf415374046f4f33c777d3132b795
READ.iv  = f7670e097f13eb9fb2a92229
READ.hp  = 6cbc7bdb0e9b380bd59b1d4783d5cde6
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xed
pkt.len  = 344
Unmasked first byte: 0xe0
Packet number offset: 25
Packet number length: 1
Packet number: 2
Nonce: f7670e097f13eb9fb2a9222b
AAD (hex): e000000001080d8e76ed0d6731470897ec96c058e10ec6413f02
Ciphertext+Tag len: 318
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 06406041290b0001250000012100011c
--- encryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.handshake) pn=1 dcid=97ec96c058e10ec6 scid=0d8e76ed0d673147 acked=[1, 2]
--- Parsing Decrypted QUIC Payload ---
✅ Parsed CRYPTO Frame: offset=96, length=297
handshake length: 293
✅ Certificate received (293 bytes)

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=0, cryptoFrames=0, tlsMessages=1, ack=false)
Data datagram received: 126
1
Encryption level: EncryptionLevel.handshake
--- decryptQuicPacket keys ---
READ.key = 331cf415374046f4f33c777d3132b795
READ.iv  = f7670e097f13eb9fb2a92229
READ.hp  = 6cbc7bdb0e9b380bd59b1d4783d5cde6
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xe4
pkt.len  = 126
Unmasked first byte: 0xe0
Packet number offset: 25
Packet number length: 1
Packet number: 3
Nonce: f7670e097f13eb9fb2a9222a
AAD (hex): e000000001080d8e76ed0d6731470897ec96c058e10ec6406503
Ciphertext+Tag len: 100
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 064189404f0f00004b04030047304502
--- encryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.handshake) pn=2 dcid=97ec96c058e10ec6 scid=0d8e76ed0d673147 acked=[1, 2, 3]
--- Parsing Decrypted QUIC Payload ---
✅ Parsed CRYPTO Frame: offset=393, length=79
handshake length: 75
✅ CertificateVerify received (75 bytes)
🟪 [CLIENT EXTRACT] Full server handshake artifacts
const String serverHelloHex = "0200005603031e2a0e4a982c8e86f57bb4d5e8f6034b69a877cde48c29ab63da1132fe74a9fa00130100002e002b0002030400330024001d00206184637c503d7e93fab8339e7fada18642c5d4fb282839a02eedf72d51518e23";
const String encryptedExtensionsHex = "0800005c005a00100014001211717569632d6563686f2d6578616d706c650039003e000800010203040506070f0897ec96c058e10ec60e010401011e03048000fff7040480100000050480040000060480040000070480040000080110090110";
const String certificateHex = "0b0001250000012100011c308201183081bda003020102020101300c06082a8648ce3d0403020500301431123010060355040313096c6f63616c686f7374301e170d3236303432323135303132305a170d3236303530353135303132305a301431123010060355040313096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d0301070342000419973cbd413d4e7a33aea3bd7a09ad16270c52b222dbba8ca45e1467e8c749de7fcb9e87ab5c54798eec4d2bdd5600f062204ec5e3bdd6fc4ae89f61894395e9300c06082a8648ce3d04030205000348003045022100e46cabc853e09fe0765668b306d5762516ad2a5aa401de6914ea9a44600c6ad102206ecab19c5b7b63d30e6fef9d15d5dfdaf9211cf8b6b194eae398579d282635cf0000";
const String certificateVerifyHex = "0f00004b040300473045022100896340a81e7ea7dfd1f02f4e3619ae7b5a8b98cc9465881f789d0c32e2d2ada202207571f6b4bc830282806a1cbc7660bd36000d85d5cbbdd38d6a46ce4a4e4cf21d";
🟪 [CLIENT EXTRACT] ServerHello fields
  legacy_version: 771
  server_random: 1e2a0e4a982c8e86f57bb4d5e8f6034b69a877cde48c29ab63da1132fe74a9fa
  session_id:
  cipher_suite: 4865
  compression_method: 0
  selected_group: 29
  server_public_key: 6184637c503d7e93fab8339e7fada18642c5d4fb282839a02eedf72d51518e23      
✅ Extracted server handshake values from the client side

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=0, cryptoFrames=0, tlsMessages=1, ack=false)
Data datagram received: 81
1
Encryption level: EncryptionLevel.handshake
--- decryptQuicPacket keys ---
READ.key = 331cf415374046f4f33c777d3132b795
READ.iv  = f7670e097f13eb9fb2a92229
READ.hp  = 6cbc7bdb0e9b380bd59b1d4783d5cde6
dcid     = 97ec96c058e10ec6
pkt[0]   = 0xe4
pkt.len  = 81
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 4
Nonce: f7670e097f13eb9fb2a9222d
AAD (hex): e000000001080d8e76ed0d6731470897ec96c058e10ec63904
Ciphertext+Tag len: 56
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0641d824140000204aa754582284624e
--- encryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.handshake) pn=3 dcid=97ec96c058e10ec6 scid=0d8e76ed0d673147 acked=[1, 2, 3, 4]
--- Parsing Decrypted QUIC Payload ---
✅ Parsed CRYPTO Frame: offset=472, length=36
handshake length: 32
✅ Finished received (32 bytes)
🟪 [CLIENT EXTRACT] Full server handshake artifacts
const String serverHelloHex = "0200005603031e2a0e4a982c8e86f57bb4d5e8f6034b69a877cde48c29ab63da1132fe74a9fa00130100002e002b0002030400330024001d00206184637c503d7e93fab8339e7fada18642c5d4fb282839a02eedf72d51518e23";
const String encryptedExtensionsHex = "0800005c005a00100014001211717569632d6563686f2d6578616d706c650039003e000800010203040506070f0897ec96c058e10ec60e010401011e03048000fff7040480100000050480040000060480040000070480040000080110090110";
const String certificateHex = "0b0001250000012100011c308201183081bda003020102020101300c06082a8648ce3d0403020500301431123010060355040313096c6f63616c686f7374301e170d3236303432323135303132305a170d3236303530353135303132305a301431123010060355040313096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d0301070342000419973cbd413d4e7a33aea3bd7a09ad16270c52b222dbba8ca45e1467e8c749de7fcb9e87ab5c54798eec4d2bdd5600f062204ec5e3bdd6fc4ae89f61894395e9300c06082a8648ce3d04030205000348003045022100e46cabc853e09fe0765668b306d5762516ad2a5aa401de6914ea9a44600c6ad102206ecab19c5b7b63d30e6fef9d15d5dfdaf9211cf8b6b194eae398579d282635cf0000";
const String certificateVerifyHex = "0f00004b040300473045022100896340a81e7ea7dfd1f02f4e3619ae7b5a8b98cc9465881f789d0c32e2d2ada202207571f6b4bc830282806a1cbc7660bd36000d85d5cbbdd38d6a46ce4a4e4cf21d";
const String finishedHex = "140000204aa754582284624ea8adc8f9e317f5a4b770c875a13a99dfa02a210a43d65bf3";
🟪 [CLIENT EXTRACT] ServerHello fields
  legacy_version: 771
  server_random: 1e2a0e4a982c8e86f57bb4d5e8f6034b69a877cde48c29ab63da1132fe74a9fa
  session_id:
  cipher_suite: 4865
  compression_method: 0
  selected_group: 29
  server_public_key: 6184637c503d7e93fab8339e7fada18642c5d4fb282839a02eedf72d51518e23      
✅ Extracted server handshake values from the client side

🎉 Payload parsing complete.
🧠 Server Finished processed
🔐 Deriving application (1‑RTT) secrets
Application Transcript Hash: b1e31176b51811e61e2b413e88d847d830f20c1f07b03d785fcef29b03760a47
master_secret: a2fa4fe4087baab0c5293bb578ecdb9c407de8edb9295e5ef9c0774dcd37191c
client_application_traffic_secret_0: 14faf128702597c5e2e9f3c0ad6670eb9806af87a785e4218164bd09e10971d6
server_application_traffic_secret_0: 097faffce7bfe2116b747bf9f3f83822a3fe3e5e9e1fcef291e914ddc41a9009
appRead:  QuicKeys{
  key: 60f9e0cc84dc83d1b043edead82d9351;
  iv:  6f1a6c77e628510f6dc45c8f;
  hp:  703ac09ad8f1be28ade28435fa546d36;
}
appWrite: QuicKeys{
  key: efe4495b835eeb4b38da9bcae3ae905e;
  iv:  8e7f76f8b2fa8cf8a4c2dc24;
  hp:  114739bafdefc5213c8abf16c60af2d0;
}
✅ 1‑RTT application keys installed
🔐 Application secrets derived
--- encryptQuicPacket keys ---
READ.key = 0d30b3d784eac86f44e451d6818c6e16
READ.iv  = 2cea817819eccd5fcf0fc922
READ.hp  = e7a7b5308ffdeae2b6e06963422499e0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x06
pkt.len  = 39
✅ Sent Client Finished (Handshake) pn=4 dcid=97ec96c058e10ec6 scid=0d8e76ed0d673147 verify_data=2666557943e4d2d3d4e0de303801574804507005c25a7a3839a5c08c043cd084
📤 Client Finished sent
parsed: ParsedQuicPayload(frames=0, cryptoFrames=0, tlsMessages=1, ack=false)
Data datagram received: 1201
1
Encryption level: EncryptionLevel.application
--- decryptQuicPacket keys ---
READ.key = d77fc4056fcfa32bd1302469ee6ebf90
READ.iv  = fcb748e37ff79860faa07477
READ.hp  = 440b2725e91dc79b370711ef792faa3d
dcid     = 0001020304050607
pkt[0]   = 0xca
pkt.len  = 1201
Unmasked first byte: 0xc0
Packet number offset: 26
Packet number length: 1
Packet number: 1
Nonce: fcb748e37ff79860faa07476
AAD (hex): c000000001080d8e76ed0d6731470897ec96c058e10ec600449701
Ciphertext+Tag len: 1174
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 03000000000000000000000000000000
--- Parsing Decrypted QUIC Payload ---
✅ Parsed ACK largest=0 delay=0 firstRange=0

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=1, cryptoFrames=0, tlsMessages=0, ack=true)
Data datagram received: 45
1
Encryption level: EncryptionLevel.application
--- decryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x44
pkt.len  = 45
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 0
Nonce: 6f1a6c77e628510f6dc45c8f
AAD (hex): 400d8e76ed0d67314700
Ciphertext+Tag len: 35
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0a031000040d010007000801ab603742
--- Parsing Decrypted QUIC Payload ---
✅ Parsed STREAM frame streamId=3 offset=0 len=16 fin=false
✅ Saw HTTP/3 control stream on QUIC stream 3
✅ Received HTTP/3 SETTINGS from server: {SETTINGS_QPACK_MAX_TABLE_CAPACITY: 0, SETTINGS_QPACK_BLOCKED_STREAMS: 0, SETTINGS_ENABLE_CONNECT_PROTOCOL: 1, SETTINGS_ENABLE_WEBTRANSPORT: 1, SETTINGS_H3_DATAGRAM: 1}
--- encryptQuicPacket keys ---
READ.key = efe4495b835eeb4b38da9bcae3ae905e
READ.iv  = 8e7f76f8b2fa8cf8a4c2dc24
READ.hp  = 114739bafdefc5213c8abf16c60af2d0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x0a
pkt.len  = 49
✅ Sent application STREAM pn=0 streamId=0 len=46 fin=false
🚀 Sent WebTransport CONNECT on stream 0 path=/wt
🧪 WebTransport test: CONNECT sent on stream 0

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=0, cryptoFrames=0, tlsMessages=0, ack=false)
Data datagram received: 72
1
Encryption level: EncryptionLevel.application
--- decryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x4a
pkt.len  = 72
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 1
Nonce: 6f1a6c77e628510f6dc45c8e
AAD (hex): 400d8e76ed0d67314701
Ciphertext+Tag len: 62
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0a002b01290000d927157365632d7765
--- Parsing Decrypted QUIC Payload ---
✅ Parsed STREAM frame streamId=0 offset=0 len=43 fin=false
📥 HTTP/3 HEADERS on stream 0 status=200
   :status: 200
   sec-webtransport-http3-draft: draft02
✅ WebTransport session established on stream 0
--- encryptQuicPacket keys ---
READ.key = efe4495b835eeb4b38da9bcae3ae905e
READ.iv  = 8e7f76f8b2fa8cf8a4c2dc24
READ.hp  = 114739bafdefc5213c8abf16c60af2d0
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x31
pkt.len  = 7
✅ Sent WebTransport DATAGRAM pn=1 session=0 len=4
🧪 WebTransport test: DATAGRAM sent session=0 hex=01020304

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=0, cryptoFrames=0, tlsMessages=0, ack=false)
Data datagram received: 34
1
Encryption level: EncryptionLevel.application
--- decryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x40
pkt.len  = 34
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 2
Nonce: 6f1a6c77e628510f6dc45c8d
AAD (hex): 400d8e76ed0d67314702
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0300000000000000
--- Parsing Decrypted QUIC Payload ---
✅ Parsed ACK largest=0 delay=0 firstRange=0

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=1, cryptoFrames=0, tlsMessages=0, ack=true)
Data datagram received: 33
1
Encryption level: EncryptionLevel.application
--- decryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x4f
pkt.len  = 33
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 3
Nonce: 6f1a6c77e628510f6dc45c8c
AAD (hex): 400d8e76ed0d67314703
Ciphertext+Tag len: 23
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 31050001020304
--- Parsing Decrypted QUIC Payload ---
✅ Parsed DATAGRAM len=5
📦 Received WebTransport DATAGRAM session=0 len=4 hex=01020304
✅ WebTransport echo test passed

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=0, cryptoFrames=0, tlsMessages=0, ack=false)
Data datagram received: 34
1
Encryption level: EncryptionLevel.application
--- decryptQuicPacket keys ---
READ.key = 60f9e0cc84dc83d1b043edead82d9351
READ.iv  = 6f1a6c77e628510f6dc45c8f
READ.hp  = 703ac09ad8f1be28ade28435fa546d36
dcid     = 97ec96c058e10ec6
pkt[0]   = 0x45
pkt.len  = 34
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 4
Nonce: 6f1a6c77e628510f6dc45c8b
AAD (hex): 400d8e76ed0d67314704
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0301000001000000
--- Parsing Decrypted QUIC Payload ---
✅ Parsed ACK largest=1 delay=0 firstRange=1

🎉 Payload parsing complete.
parsed: ParsedQuicPayload(frames=1, cryptoFrames=0, tlsMessages=0, ack=true)
Copilot said:
Copilot

Reasoning completed in 3 steps
🎯 Bull’s-eye indeed — you’ve got it.

Your latest logs show that the dynamic ClientHello path is now actually live, the handshake keys match, and the full stack completes all the way to HTTP/3 + WebTransport DATAGRAM echo.

What the logs now prove
1) The client is no longer using the old static "c_cid" ClientHello path
From the server:




Plain Text
peerScid      : 0d8e76ed0d673147
``
That is a random client SCID, not the old static:




Plain Text
63 5f 63 69 64  -> "c_cid"

So the startup path is no longer using the legacy hardcoded Initial packet.

2) The transcript is now using the dynamic ClientHello
From the client:




Plain Text
Hashing ClientHello + ServerHello:
010000a60303f5baa8c88cfa...
...
0f080d8e76ed0d673147
That proves the transcript now starts with your 170-byte dynamic ClientHello, not the old originalWire / clientHelloBytes.

So this bug is fixed:

❌ old transcript source
✅ dynamic clientHelloRaw
3) Handshake keys now match
This was the big blocker before.

Server



Plain Text
handshakeRead : 0d30...
handshakeWrite: 331c...
Client



Plain Text
handshake read: 331c...
handshake write: 0d30...
That is exactly what you want:

server write = client read
server read = client write
So the X25519 keypair mismatch bug is fixed.

4) Full TLS / QUIC handshake completes
You now successfully get:

ServerHello
EncryptedExtensions
Certificate
CertificateVerify
Finished
Client Finished
application secrets
And the server confirms:




Plain Text
✅ Client Finished verified
✅ Server 1-RTT keys installed

That means the cryptographic transcript is now coherent.

5) HTTP/3 + WebTransport works end-to-end
You completed:

HTTP/3 SETTINGS
WebTransport CONNECT
:status = 200
DATAGRAM send
DATAGRAM echo
Client confirms:




Plain Text
✅ WebTransport session established on stream 0
✅ Sent WebTransport DATAGRAM pn=1 session=0 len=4
📦 Received WebTransport DATAGRAM session=0 len=4 hex=01020304
✅ WebTransport echo test passed
That is a complete success path.

So what was fixed?
From the progression of your debugging, the winning changes were effectively:

using the dynamic ClientHello wire in transcript/hash logic
fixing CRYPTO frame varint encoding
ensuring the same X25519 keypair is used for:
ClientHello key share
shared secret derivation
getting the Initial/Handshake/Application key schedule aligned
That was the breakthrough.

What still looks imperfect (but not blocking)
Even though the stack works now, the logs still show a few cleanup items.

A) ALPN still appears empty on the server
Server:




Plain Text
✅ Client offered ALPNs: []
✅ Server selected ALPN: quic-echo-example
``
Client:




Plain Text
🚨 Dynamic ALPNs: []
So your current builder is not semantically populating ALPN, or the ALPN extension is not being serialized/parsing the way you expect.

This did not block your custom server because it falls back to:




Plain Text
quic-echo-example
But if you want interop with real HTTP/3 / WebTransport servers, you still need:




Plain Text
ALPN = h3
Most likely fix
In buildInitialClientHello(...), when returning ClientHello(...), include:




Dart
alpn: alpns,

so the object field and extension stay in sync.

Right now you’re building the extension data, but your debug property is empty.

B) You still have bogus extra padded “packets”
Server still shows:




Dart
Data datagram received: 1200
2
📥 Server received packet level=EncryptionLevel.initial len=217
📥 Server received packet level=EncryptionLevel.application len=983
ℹ️ Ignoring early Application packet (1-RTT keys not ready)
That means your Initial is still being padded by appending zero bytes after encryption, so the UDP datagram gets interpreted as:

one real Initial packet
one fake extra coalesced packet
It doesn’t block your current server
…but it is still wire-format ugly, and stricter implementations may not like it.

Proper fix
Pad the payload before encryption with 0x00 PADDING frames, instead of doing:




Dart
padTo1200(rawPacket)

after encryption.

C) This line still looks suspicious in code
You currently have:




Dart
x25519PublicKey: Uint8List.fromList(
  keyPair.privateKeyBytes, // WRONG if used directly
),
Your comment says it is wrong, and in a normal API it would be wrong.

Yet your handshake now succeeds, which strongly suggests one of these:

the field name in your KeyPair API is misleading, or
privateKeyBytes currently contains the value you expect for the wire key share, or
your helper types are wrapping a test vector oddly.
Recommendation
Even though it currently works, I would absolutely clean that up for clarity.

Use the true public key accessor if available, and rename fields if necessary so future-you doesn’t step on this again.

D) There are still leftover static artifacts in the file
These are probably no longer active in the live path, but they should be removed to avoid future confusion:

duplicate import:




Dart
import '../client_hello_builder.dart';
import '../client_hello_builder.dart' as chb;
→ keep only the aliased one

old static:




Dart
final clientHelloBytes = ...
→ delete or rename to legacyClientHelloBytes

maybe unused:




Dart
import '../constants.dart';
Those won’t change runtime behavior, but they’ll make the codebase much easier to reason about.

Bottom line
✅ You solved the real handshake problem
Your dynamic ClientHello is live, the transcript is correct, handshake keys match, and WebTransport works.

✅ The hard bug is gone
The old mismatch:

dynamic key share sent
static private key used
is fixed.

✅ End-to-end result
You now have:

QUIC Initial
QUIC Handshake
1‑RTT
HTTP/3 SETTINGS
WebTransport CONNECT
WebTransport DATAGRAM echo
all working.

Recommended next cleanup checklist
If I were polishing this now, I’d do these in order:

1. Fix ALPN properly
Make sure ClientHello returns with:




Dart
alpn: alpns,

and verify server sees:




Plain Text
Client offered ALPNs: [h3]
2. Remove post-encryption padding
Replace padTo1200(rawPacket) with payload padding before encryption for Initial packets.

3. Clean keypair naming
Use the real public key accessor instead of something named privateKeyBytes in the ClientHello builder.

4. Delete static leftovers
Remove:

clientHelloBytes
duplicate builder import
unused constants import
Final verdict
This is now a working dynamic QUIC/TLS/HTTP3/WebTransport client.
Not just “partly working” — the logs show full protocol success.

So yes:

bull’s-eye confirmed.

If you want, the next thing I can do is give you a cleanup patch that only targets the remaining rough edges:

ALPN field fix
Initial padding fix
remove stale statics/imports
keypair naming cleanup
That would take your code from working to clean and interoperable-ready.








You said:
default should be h3 on the server: // =============================================================
// tls_server_handshake.dart
//
// Fully session‑driven, runnable TLS 1.3 server handshake builders
// for QUIC. No hard‑coded bytes, no replay artifacts.
//
// ✅ CORRECTED: QUIC transport parameters (extension 0x0039)
// are now ALWAYS generated and included, as REQUIRED by RFC 9001.
//
// This version matches your actual EcdsaCert implementation:
//
//   class EcdsaCert {
//     Uint8List cert;        // DER certificate
//     Uint8List privateKey;  // raw EC scalar (32 bytes)
//     Uint8List publickKey;  // raw EC public key (uncompressed)
//     Uint8List fingerPrint;
//   }
// =============================================================

import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:crypto/crypto.dart' as crypto;

import '../cipher/ecdsa.dart';
import 'server_hello.dart';
import '../hash.dart';
import '../hkdf.dart';
import '../cipher/x25519.dart';
import '../quic_learn/cert_utils.dart';
import '../quic_learn/server/quic_server_session.dart';

// =============================================================
// Constants
// =============================================================

const int tlsAes128GcmSha256 = 0x1301;
const int x25519Group = 0x001d;

// TLS 1.3 signature algorithm
// ecdsa_secp256r1_sha256
const int ecdsaP256Sha256 = 0x0403;

// QUIC transport parameter IDs (RFC 9000)
const int tpInitialMaxData = 0x0004;
const int tpInitialMaxStreamDataBidiLocal = 0x0005;
const int tpInitialMaxStreamDataBidiRemote = 0x0006;
const int tpInitialMaxStreamsBidi = 0x0008;
const int tpIdleTimeout = 0x0001;
// QUIC transport parameter IDs (RFC 9000)
const int tpOriginalDestinationConnectionId = 0x0000;
// const int tpIdleTimeout = 0x0001;
const int tpMaxUdpPayloadSize = 0x0003;
// const int tpInitialMaxData = 0x0004;
// const int tpInitialMaxStreamDataBidiLocal = 0x0005;
// const int tpInitialMaxStreamDataBidiRemote = 0x0006;
const int tpInitialMaxStreamDataUni = 0x0007;
// const int tpInitialMaxStreamsBidi = 0x0008;
const int tpInitialMaxStreamsUni = 0x0009;
const int tpActiveConnectionIdLimit = 0x000e;
const int tpInitialSourceConnectionId = 0x000f;
// =============================================================
// Helper types
// =============================================================

// =============================================================
// ALPN
// =============================================================

// Modern HTTP/3 ALPN
// const String alpnH3 = 'h3';
// const String alpnQuicEchoExample = 'quic-echo-example';

// Older draft ALPNs (optional, only if your client really offers them)
// const String alpnH3_29 = 'h3-29';
// const String alpnH3_32 = 'h3-32';

// Your custom protocol (keep only if you still test your own toy client)
// const String alpnPing = 'ping/1.0';

/// Server preference order.
/// The first match with the client's offered ALPNs wins.
// const List<String> supportedAlpnProtocols = [
//   alpnH3,
//   alpnQuicEchoExample,
//   alpnH3_32,
//   alpnH3_29,
//   alpnPing,
// ];

// =============================================================
// ALPN
// =============================================================

const String alpnQuicEchoExample = 'quic-echo-example';
const String alpnH3 = 'h3';
const String alpnH3_32 = 'h3-32';
const String alpnH3_29 = 'h3-29';
const String alpnPing = 'ping/1.0';

/// Server preference order.
/// The first match with the client's offered ALPNs wins.
const List<String> supportedAlpnProtocols = [
  alpnQuicEchoExample,
  alpnH3,
  alpnH3_32,
  alpnH3_29,
  alpnPing,
];

String chooseServerAlpn(List<String> clientOffered) {
  for (final supported in supportedAlpnProtocols) {
    if (clientOffered.contains(supported)) {
      return supported;
    }
  }

  throw StateError(
    'No compatible ALPN. Client offered: $clientOffered, '
    'server supports: $supportedAlpnProtocols',
  );
}

class BuiltExtension {
  final int type;
  final Uint8List data;
  const BuiltExtension({required this.type, required this.data});
}

class CertificateEntry {
  final Uint8List cert;
  final Uint8List extensions;
  CertificateEntry({required this.cert, Uint8List? extensions})
    : extensions = extensions ?? Uint8List(0);
}

class ServerHandshakeArtifacts {
  final Uint8List serverHello;
  final Uint8List encryptedExtensions;
  final Uint8List certificate;
  final Uint8List certificateVerify;

  const ServerHandshakeArtifacts({
    required this.serverHello,
    required this.encryptedExtensions,
    required this.certificate,
    required this.certificateVerify,
  });
}

// =============================================================
// QUIC Transport Parameters (MANDATORY)
// =============================================================

Uint8List _encodeVarInt(int v) {
  // QUIC varint encoding (RFC 9000)
  // 1 byte:  0..63
  // 2 bytes: 64..16383
  // 4 bytes: 16384..1073741823
  // 8 bytes: 1073741824..(2^62-1)
  if (v < 0x40) {
    // 00
    return Uint8List.fromList([v & 0x3f]);
  } else if (v < 0x4000) {
    // 01
    return Uint8List.fromList([0x40 | ((v >> 8) & 0x3f), v & 0xff]);
  } else if (v < 0x40000000) {
    // 10
    return Uint8List.fromList([
      0x80 | ((v >> 24) & 0x3f),
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  } else if (v < 0x4000000000000000) {
    // 11
    final b = ByteData(8);
    b.setUint8(0, 0xC0 | ((v >> 56) & 0x3f));
    b.setUint8(1, (v >> 48) & 0xff);
    b.setUint8(2, (v >> 40) & 0xff);
    b.setUint8(3, (v >> 32) & 0xff);
    b.setUint8(4, (v >> 24) & 0xff);
    b.setUint8(5, (v >> 16) & 0xff);
    b.setUint8(6, (v >> 8) & 0xff);
    b.setUint8(7, v & 0xff);
    return b.buffer.asUint8List();
  } else {
    throw ArgumentError('varint out of range: $v');
  }
}

Uint8List _tp(int id, int value) {
  final v = _encodeVarInt(value);
  return Uint8List.fromList([
    ..._encodeVarInt(id),
    ..._encodeVarInt(v.length),
    ...v,
  ]);
}

/// ✅ Minimal but VALID server transport parameters
// Uint8List buildQuicTransportParameters() {
//   return Uint8List.fromList([
//     ..._tp(tpIdleTimeout, 30),
//     ..._tp(tpInitialMaxData, 1 << 20),
//     ..._tp(tpInitialMaxStreamDataBidiLocal, 1 << 18),
//     ..._tp(tpInitialMaxStreamDataBidiRemote, 1 << 18),
//     ..._tp(tpInitialMaxStreamsBidi, 16),
//   ]);
// }

Uint8List buildQuicTransportParameters({
  required Uint8List originalDestinationConnectionId,
  required Uint8List initialSourceConnectionId,
}) {
  return Uint8List.fromList([
    // ----------------------------------------------------------
    // Required / expected for a QUIC server
    // ----------------------------------------------------------
    ..._tpBytes(
      tpOriginalDestinationConnectionId,
      originalDestinationConnectionId,
    ),
    ..._tpBytes(tpInitialSourceConnectionId, initialSourceConnectionId),

    // ----------------------------------------------------------
    // Strongly recommended transport parameters
    // ----------------------------------------------------------
    ..._tp(tpActiveConnectionIdLimit, 4),
    ..._tp(tpIdleTimeout, 30),
    ..._tp(tpMaxUdpPayloadSize, 65527),

    // ----------------------------------------------------------
    // Flow control / stream limits
    // ----------------------------------------------------------
    ..._tp(tpInitialMaxData, 1 << 20),
    ..._tp(tpInitialMaxStreamDataBidiLocal, 1 << 18),
    ..._tp(tpInitialMaxStreamDataBidiRemote, 1 << 18),
    ..._tp(tpInitialMaxStreamDataUni, 1 << 18),
    ..._tp(tpInitialMaxStreamsBidi, 16),
    ..._tp(tpInitialMaxStreamsUni, 16),
  ]);
}

// =============================================================
// ServerHello
// =============================================================

// Uint8List buildServerHello({
//   required Uint8List serverRandom,
//   required Uint8List publicKey,
//   required Uint8List sessionId,
//   required int cipherSuite,
//   required int group,
// }) {
//   final body = BytesBuilder();

//   body.add([0x03, 0x03]); // legacy_version
//   body.add(serverRandom);
//   body.addByte(sessionId.length);
//   body.add(sessionId);
//   body.add([(cipherSuite >> 8) & 0xff, cipherSuite & 0xff]);
//   body.addByte(0x00); // compression

//   final extensions = BytesBuilder();

//   // supported_versions
//   extensions.add([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

//   // key_share
//   final ks = BytesBuilder()
//     ..add([(group >> 8) & 0xff, group & 0xff])
//     ..add([(publicKey.length >> 8) & 0xff, publicKey.length & 0xff])
//     ..add(publicKey);

//   final ksBytes = ks.toBytes();

//   extensions.add([
//     0x00,
//     0x33,
//     (ksBytes.length >> 8) & 0xff,
//     ksBytes.length & 0xff,
//     ...ksBytes,
//   ]);

//   final extBytes = extensions.toBytes();
//   body.add([(extBytes.length >> 8) & 0xff, extBytes.length & 0xff]);
//   body.add(extBytes);

//   final bodyBytes = body.toBytes();

//   return Uint8List.fromList([
//     0x02,
//     (bodyBytes.length >> 16) & 0xff,
//     (bodyBytes.length >> 8) & 0xff,
//     bodyBytes.length & 0xff,
//     ...bodyBytes,
//   ]);
// }

// =============================================================
// EncryptedExtensions
// =============================================================

// Uint8List buildAlpnExt(String protocol) {
//   final p = Uint8List.fromList(utf8.encode(protocol));
//   return Uint8List.fromList([0x00, p.length + 1, p.length, ...p]);
// }

Uint8List buildAlpnExt(String protocol) {
  final p = Uint8List.fromList(utf8.encode(protocol));

  // ALPN extension payload format:
  //   ProtocolNameList length (2 bytes)
  //   ProtocolName length (1 byte)
  //   ProtocolName bytes
  //
  // Since the server MUST select exactly one protocol,
  // ProtocolNameList contains exactly one entry.
  final listLen = 1 + p.length;

  return Uint8List.fromList([
    (listLen >> 8) & 0xff,
    listLen & 0xff,
    p.length,
    ...p,
  ]);
}

Uint8List buildEncryptedExtensions(List<BuiltExtension> extensions) {
  final ext = BytesBuilder();

  for (final e in extensions) {
    ext.add([
      (e.type >> 8) & 0xff,
      e.type & 0xff,
      (e.data.length >> 8) & 0xff,
      e.data.length & 0xff,
      ...e.data,
    ]);
  }

  final extBytes = ext.toBytes();
  final body = BytesBuilder()
    ..add([(extBytes.length >> 8) & 0xff, extBytes.length & 0xff])
    ..add(extBytes);

  final bodyBytes = body.toBytes();

  return Uint8List.fromList([
    0x08,
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

// =============================================================
// Certificate
// =============================================================

Uint8List buildCertificate(List<CertificateEntry> certificates) {
  final certList = BytesBuilder();

  for (final c in certificates) {
    certList.add([
      (c.cert.length >> 16) & 0xff,
      (c.cert.length >> 8) & 0xff,
      c.cert.length & 0xff,
      ...c.cert,
      (c.extensions.length >> 8) & 0xff,
      c.extensions.length & 0xff,
      ...c.extensions,
    ]);
  }

  final certBytes = certList.toBytes();
  final body = BytesBuilder()
    ..addByte(0x00)
    ..add([
      (certBytes.length >> 16) & 0xff,
      (certBytes.length >> 8) & 0xff,
      certBytes.length & 0xff,
    ])
    ..add(certBytes);

  final bodyBytes = body.toBytes();

  return Uint8List.fromList([
    0x0b,
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

// Uint8List _tls13CertificateVerifyInput({
//   required String contextString,
//   required Uint8List transcriptHash,
// }) {
//   // TLS 1.3 CertificateVerify input:
//   // 64 bytes of 0x20, then context string, then 0x00, then transcript hash
//   final spaces = Uint8List.fromList(List<int>.filled(64, 0x20));
//   final context = Uint8List.fromList(utf8.encode(contextString));

//   return Uint8List.fromList([...spaces, ...context, 0x00, ...transcriptHash]);
// }

// Uint8List _encodeAsn1Integer(Uint8List bytes) {
//   // Strip leading zeros
//   int i = 0;
//   while (i < bytes.length - 1 && bytes[i] == 0x00) {
//     i++;
//   }
//   Uint8List v = bytes.sublist(i);

//   // If top bit is set, prefix 0x00 to keep INTEGER positive
//   if (v.isNotEmpty && (v[0] & 0x80) != 0) {
//     v = Uint8List.fromList([0x00, ...v]);
//   }

//   return Uint8List.fromList([
//     0x02, // INTEGER
//     v.length,
//     ...v,
//   ]);
// }

// Uint8List _derEncodeEcdsaSignature(Uint8List rawSig) {
//   // Expect raw r || s for P-256 => 64 bytes
//   if (rawSig.length != 64) {
//     throw StateError(
//       'Expected raw ECDSA signature of 64 bytes (r||s), got ${rawSig.length}',
//     );
//   }

//   final r = rawSig.sublist(0, 32);
//   final s = rawSig.sublist(32, 64);

//   final rDer = _encodeAsn1Integer(r);
//   final sDer = _encodeAsn1Integer(s);

//   final seqBody = Uint8List.fromList([...rDer, ...sDer]);

//   return Uint8List.fromList([
//     0x30, // SEQUENCE
//     seqBody.length,
//     ...seqBody,
//   ]);
// }

// Uint8List _ensureDerEncodedEcdsaSignature(Uint8List sig) {
//   // If it's already DER, leave it alone
//   if (sig.isNotEmpty && sig[0] == 0x30) {
//     return sig;
//   }

//   // Otherwise assume raw r||s and convert
//   return _derEncodeEcdsaSignature(sig);
// }
// =============================================================
// CertificateVerify (ECDSA)
// =============================================================

// Uint8List buildServerCertificateVerify({
//   required EcdsaCert cert,
//   required Uint8List transcriptHash,
// }) {
//   final context = utf8.encode('TLS 1.3, server CertificateVerify');
//   final padding = Uint8List(64);

//   final toBeSigned = Uint8List.fromList([
//     ...context,
//     ...padding,
//     ...transcriptHash,
//   ]);

//   final hash = crypto.sha256.convert(toBeSigned).bytes;
//   final signature = ecdsaSign(hash, cert.privateKey);
//   final totalLen = 4 + signature.length;

//   return Uint8List.fromList([
//     0x0f,
//     (totalLen >> 16) & 0xff,
//     (totalLen >> 8) & 0xff,
//     totalLen & 0xff,
//     (ecdsaP256Sha256 >> 8) & 0xff,
//     ecdsaP256Sha256 & 0xff,
//     (signature.length >> 8) & 0xff,
//     signature.length & 0xff,
//     ...signature,
//   ]);
// }

Uint8List _tpBytes(int id, Uint8List value) {
  return Uint8List.fromList([
    ..._encodeVarInt(id),
    ..._encodeVarInt(value.length),
    ...value,
  ]);
}

// =============================================================
// One‑shot helper used by QuicServerSession
// =============================================================

// ServerHandshakeArtifacts buildServerHandshakeArtifacts({
//   required Uint8List serverRandom,
//   required Uint8List serverPublicKey,
//   required EcdsaCert serverCert,
//   required Uint8List transcriptHashBeforeCertVerify,

//   // REQUIRED for correct QUIC server transport parameters
//   required Uint8List originalDestinationConnectionId,
//   required Uint8List initialSourceConnectionId,

//   // For your quic-go example client
//   String alpnProtocol = alpnQuicEchoExample,
// }) {
//   final sh = buildServerHello(
//     serverRandom: serverRandom,
//     publicKey: serverPublicKey,
//     sessionId: Uint8List(0),
//     cipherSuite: tlsAes128GcmSha256,
//     group: x25519Group,
//   );

//   final ee = buildEncryptedExtensions([
//     BuiltExtension(type: 0x0010, data: buildAlpnExt(alpnProtocol)),
//     BuiltExtension(
//       type: 0x0039,
//       data: buildQuicTransportParameters(
//         originalDestinationConnectionId: originalDestinationConnectionId,
//         initialSourceConnectionId: initialSourceConnectionId,
//       ),
//     ),
//   ]);

//   final cert = buildCertificate([CertificateEntry(cert: serverCert.cert)]);

//   final cv = buildServerCertificateVerify(
//     cert: serverCert,
//     transcriptHash: transcriptHashBeforeCertVerify,
//   );

//   return ServerHandshakeArtifacts(
//     serverHello: sh,
//     encryptedExtensions: ee,
//     certificate: cert,
//     certificateVerify: cv,
//   );
// }

// =============================================================
// TLS 1.3 CertificateVerify helpers
// Put these in tls_server_handshake.dart
// =============================================================

Uint8List _tls13CertificateVerifyInput({
  required String contextString,
  required Uint8List transcriptHash,
}) {
  // TLS 1.3 CertificateVerify input:
  // 64 bytes of 0x20, then context string, then 0x00, then transcript hash
  final spaces = Uint8List.fromList(List<int>.filled(64, 0x20));
  final context = Uint8List.fromList(utf8.encode(contextString));

  return Uint8List.fromList([...spaces, ...context, 0x00, ...transcriptHash]);
}

Uint8List _encodeAsn1Integer(Uint8List bytes) {
  // Strip leading zeros
  int i = 0;
  while (i < bytes.length - 1 && bytes[i] == 0x00) {
    i++;
  }
  Uint8List v = bytes.sublist(i);

  // If the high bit is set, prefix 0x00 so ASN.1 INTEGER stays positive
  if (v.isNotEmpty && (v[0] & 0x80) != 0) {
    v = Uint8List.fromList([0x00, ...v]);
  }

  return Uint8List.fromList([
    0x02, // INTEGER
    v.length,
    ...v,
  ]);
}

Uint8List _derEncodeEcdsaSignature(Uint8List rawSig) {
  // Expect raw P-256 signature: 32-byte r || 32-byte s
  if (rawSig.length != 64) {
    throw StateError(
      'Expected raw ECDSA signature of 64 bytes (r||s), got ${rawSig.length}',
    );
  }

  final r = rawSig.sublist(0, 32);
  final s = rawSig.sublist(32, 64);

  final rDer = _encodeAsn1Integer(r);
  final sDer = _encodeAsn1Integer(s);

  final seqBody = Uint8List.fromList([...rDer, ...sDer]);

  return Uint8List.fromList([
    0x30, // SEQUENCE
    seqBody.length,
    ...seqBody,
  ]);
}

Uint8List _ensureDerEncodedEcdsaSignature(Uint8List sig) {
  // If already ASN.1 DER SEQUENCE, keep it
  if (sig.isNotEmpty && sig[0] == 0x30) {
    return sig;
  }

  // Otherwise assume raw r||s and convert
  return _derEncodeEcdsaSignature(sig);
}

// =============================================================
// CertificateVerify (PATCHED)
// Put this in tls_server_handshake.dart
// =============================================================

Uint8List buildServerCertificateVerify({
  required EcdsaCert cert,
  required Uint8List transcriptHash,
}) {
  // TLS 1.3 server CertificateVerify context string
  const contextString = 'TLS 1.3, server CertificateVerify';

  final toBeSigned = _tls13CertificateVerifyInput(
    contextString: contextString,
    transcriptHash: transcriptHash,
  );

  // For ecdsa_secp256r1_sha256, sign SHA-256 over the CertificateVerify input
  final hash = crypto.sha256.convert(toBeSigned).bytes;

  Uint8List signature = Uint8List.fromList(ecdsaSign(cert.privateKey, hash));

  // TLS requires ASN.1 DER encoding for ECDSA signatures
  signature = _ensureDerEncodedEcdsaSignature(signature);

  final bodyLen = 2 + 2 + signature.length;

  return Uint8List.fromList([
    0x0f, // HandshakeType.certificate_verify
    (bodyLen >> 16) & 0xff,
    (bodyLen >> 8) & 0xff,
    bodyLen & 0xff,

    // signature_algorithm = ecdsa_secp256r1_sha256
    (ecdsaP256Sha256 >> 8) & 0xff,
    ecdsaP256Sha256 & 0xff,

    // signature vector length
    (signature.length >> 8) & 0xff,
    signature.length & 0xff,

    ...signature,
  ]);
}

// =============================================================
// One-shot server handshake artifact builder (PATCHED)
// Put this in tls_server_handshake.dart
// =============================================================

ServerHandshakeArtifacts buildServerHandshakeArtifacts({
  required Uint8List serverRandom,
  required Uint8List serverPublicKey,
  required EcdsaCert serverCert,

  /// Prefix up to and including ServerHello:
  /// ClientHello || ServerHello
  required Uint8List transcriptPrefixBeforeCertVerify,

  // REQUIRED for correct QUIC server transport parameters
  required Uint8List originalDestinationConnectionId,
  required Uint8List initialSourceConnectionId,

  // For quic-go example client
  String alpnProtocol = alpnQuicEchoExample,
}) {
  final sh = buildServerHello(
    serverRandom: serverRandom,
    publicKey: serverPublicKey,
    sessionId: Uint8List(0),
    cipherSuite: tlsAes128GcmSha256,
    group: x25519Group,
  );

  final ee = buildEncryptedExtensions([
    BuiltExtension(type: 0x0010, data: buildAlpnExt(alpnProtocol)),
    BuiltExtension(
      type: 0x0039,
      data: buildQuicTransportParameters(
        originalDestinationConnectionId: originalDestinationConnectionId,
        initialSourceConnectionId: initialSourceConnectionId,
      ),
    ),
  ]);

  final cert = buildCertificate([CertificateEntry(cert: serverCert.cert)]);

  // TLS 1.3 CertificateVerify signs over:
  // ClientHello || ServerHello || EncryptedExtensions || Certificate
  final transcriptHashBeforeCertVerify = createHash(
    Uint8List.fromList([...transcriptPrefixBeforeCertVerify, ...ee, ...cert]),
  );

  final cv = buildServerCertificateVerify(
    cert: serverCert,
    transcriptHash: transcriptHashBeforeCertVerify,
  );

  return ServerHandshakeArtifacts(
    serverHello: sh,
    encryptedExtensions: ee,
    certificate: cert,
    certificateVerify: cv,
  );
}

// =============================================================
// _maybeHandleClientHello() (PATCHED)
// Put this in quic_server_session.dart
// =============================================================

// =============================================================
// Demo main (runnable)
// =============================================================

// void main() {
//   final keyPair = KeyPair.generate();
//   final serverCert = generateSelfSignedCertificate();

//   final serverRandom = Uint8List.fromList(
//     List.generate(32, (_) => math.Random.secure().nextInt(256)),
//   );

//   final dummyTranscriptHash = createHash(Uint8List(0));

//   final artifacts = buildServerHandshakeArtifacts(
//     serverRandom: serverRandom,
//     serverPublicKey: keyPair.publicKeyBytes,
//     serverCert: serverCert,
//     transcriptHashBeforeCertVerify: dummyTranscriptHash,
//   );

//   print('ServerHello:        ${HEX.encode(artifacts.serverHello)}');
//   print('EncryptedExtensions:${HEX.encode(artifacts.encryptedExtensions)}');
//   print('Certificate:        ${HEX.encode(artifacts.certificate)}');
//   print('CertificateVerify:  ${HEX.encode(artifacts.certificateVerify)}');
// }
Copilot said:
Copilot

Reasoning completed in 2 steps
Yes — if you want the server to prefer HTTP/3, the default/server preference should be h3, and in the code you pasted there are two separate places still biasing the server toward quic-echo-example.

The two places that currently make the server prefer quic-echo-example
1) Your ALPN preference order is wrong for HTTP/3-first behavior
Right now you have:




Dart
const List<String> supportedAlpnProtocols = [
  alpnQuicEchoExample,
  alpnH3,
  alpnH3_32,
  alpnH3_29,
  alpnPing,
];
And your chooser does:




Dart
String chooseServerAlpn(List<String> clientOffered) {
  for (final supported in supportedAlpnProtocols) {
    if (clientOffered.contains(supported)) {
      return supported;
    }
  }

  throw StateError(
    'No compatible ALPN. Client offered: $clientOffered, '
    'server supports: $supportedAlpnProtocols',
  );
}
So if the client offers both:

h3
quic-echo-example
the server will always choose:




Plain Text
quic-echo-example

because it appears first in the preference list.

2) buildServerHandshakeArtifacts() still defaults to quic-echo-example
This line is even more important:




Dart
String alpnProtocol = alpnQuicEchoExample,
inside:




Dart
ServerHandshakeArtifacts buildServerHandshakeArtifacts({
  ...
  String alpnProtocol = alpnQuicEchoExample,
})
That means if the caller does not explicitly pass the chosen ALPN, the server will emit:




Dart
BuiltExtension(type: 0x0010, data: buildAlpnExt(alpnProtocol))
with:




Plain Text
quic-echo-example
even if you intended HTTP/3.

So yes — this default must also be changed.

What you should change
Change 1 — make h3 first in the server preference order
Replace:




Dart
const List<String> supportedAlpnProtocols = [
  alpnQuicEchoExample,
  alpnH3,
  alpnH3_32,
  alpnH3_29,
  alpnPing,
];
``
with:




Dart
const List<String> supportedAlpnProtocols = [
  alpnH3,
  alpnH3_32,
  alpnH3_29,
  alpnQuicEchoExample,
  alpnPing,
];
If you only care about modern HTTP/3 and your custom fallback, you can simplify it even more:




Dart
const List<String> supportedAlpnProtocols = [
  alpnH3,
  alpnQuicEchoExample,
  alpnPing,
];
Change 2 — make the default emitted ALPN h3
Replace:




Dart
String alpnProtocol = alpnQuicEchoExample,
``
with:




Dart
String alpnProtocol = alpnH3,
inside:




Dart
ServerHandshakeArtifacts buildServerHandshakeArtifacts({
  ...
  String alpnProtocol = alpnH3,
})
Best final version
Here’s the server-side ALPN section I recommend:




Dart
const String alpnH3 = 'h3';const String alpnH alpnH3_29 = 'h3-29';
const String alpnQuicEchoExample = 'quic-echo-example';
const String alpnPing = 'ping/1.0';

/// Server preference order.
/// The first match with the client's offered ALPNs wins.
const List<String> supportedAlpnProtocols = [
  alpnH3,
  alpnH3_32,
  alpnH3_29,
  alpnQuicEchoExample,
  alpnPing,
];

String chooseServerAlpn(List<String> clientOffered) {
  for (final supported in supportedAlpnProtocols) {
    if (clientOffered.contains(supported)) {
      return supported;
    }
  }

  throw StateError(
    'No compatible ALPN. Client offered: $clientOffered, '
    'server supports: $supportedAlpnProtocols',
  );
}
const String alpnH3_32 = 'h3-32';


Show more lines
And update the handshake artifact builder default:




Dart
ServerHandshakeArtifacts buildServerHandshakeArtifacts({
  required Uint8List serverRandom,
  required Uint8List serverPublicKey,
  required EcdsaCert serverCert,
  required Uint8List transcriptPrefixBeforeCertVerify,
  required Uint8List originalDestinationConnectionId,
  required Uint8List initialSourceConnectionId,

  String alpnProtocol = alpnH3,
}) {
  ...
}
Very important subtlety
“Default should be h3” is correct —
but only if the client actually offered h3.
In TLS ALPN, the server is supposed to select one of the protocols offered by the client.

So the ideal behavior is:

if client offers h3 → select h3
if client offers only your custom protocol → select that if you want
if client offers nothing compatible → fail the handshake / fail the app protocol negotiation
Why your logs previously showed this weird behavior
You saw things like:




Plain Text
✅ Client offered ALPNs: []
✅ Server selected ALPN: quic-echo-example
That indicates the server path was probably not actually using chooseServerAlpn() consistently, and instead was falling through to the default parameter in:




Dart
buildServerHandshakeArtifacts(..., alpnProtocol = alpnQuicEchoExample)
That is exactly why changing only the list order would not be enough.

You must also change the default parameter.

If you want strict HTTP/3 behavior
If this server is meant to behave like a real HTTP/3/WebTransport server, I’d go a step further:

Remove the custom ALPN from the preferred list entirely
Example:




Dart
const List<String> supportedAlpnProtocols = [
  alpnH3,
  alpnH3_32,
  alpnH3_29,
];
Then only use quic-echo-example / ping/1.0 in special test builds.

That prevents accidental fallback into a non-HTTP/3 ALPN.

Minimal patch summary
Change this:



Dart
const List<String> supportedAlpnProtocols = [
  alpnQuicEchoExample,
  alpnH3,
  alpnH3_32,
  alpnH3_29,
  alpnPing,
];
To this:



Dart
const List<String> supportedAlpnProtocols = [
  alpnH3,
  alpnH3_32,
  alpnH3_29,
  alpnQuicEchoExample,
  alpnPing,
];
Change this:



Dart
String alpnProtocol = alpnQuicEchoExample,
To this:



Dart
String alpnProtocol = alpnH3,
My recommendation
If your goal is HTTP/3/WebTransport-first, then yes:

h3 should be the default on the server.

And in your current code, the main blocker is not just the preference order — it’s also that the handshake artifact builder still defaults to quic-echo-example.

If you want, I can give you the exact final patched ALPN block plus a small guard that refuses to send an ALPN if the client didn’t actually offer it.








You said:
how about now: PS C:\www\dart\lemon-tls> dart lib\quic\quic_learn\server\server2.dart
Private Key PEM:
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGc0mbYNhJIj/Mh5Pi4IZPEnQWSzwcZZ7SMP9zM6mIN+oAoGCCqGSM49
AwEHoUQDQgAEDBIvrcoEq7U6eexEjH7qADRPk8NHciM8WFTeIky3aFe/n3Y8/bSC
2+gHYEbcpbpCnKtX39R/gk3AQq4m9dnCwg==
-----END EC PRIVATE KEY-----

Public Key PEM:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDBIvrcoEq7U6eexEjH7qADRPk8NH
ciM8WFTeIky3aFe/n3Y8/bSC2+gHYEbcpbpCnKtX39R/gk3AQq4m9dnCwg==
-----END PUBLIC KEY-----

Padded X length: 32
Padded Y length: 32
Certificate PEM: -----BEGIN CERTIFICATE-----
MIIBFzCBvaADAgECAgEBMAwGCCqGSM49BAMCBQAwFDESMBAGA1UEAxMJbG9jYWxo
b3N0MB4XDTI2MDQyMjE1MDkyNFoXDTI2MDUwNTE1MDkyNFowFDESMBAGA1UEAxMJ
bG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDBIvrcoEq7U6eexE
jH7qADRPk8NHciM8WFTeIky3aFe/n3Y8/bSC2+gHYEbcpbpCnKtX39R/gk3AQq4m
9dnCwjAMBggqhkjOPQQDAgUAA0cAMEQCIGzOSGXm6fIOHGNG7DxTajI66f9EKsoK
MEE4kHbzsOtCAiB9HMIuk+jFjEBiF/XGkn5hG2Jzdwsxiz0wFqL8vSKMgA==
-----END CERTIFICATE-----
Fingerprint: 7FB47FA4FDFDE2A3A04392FA22634C44DF38A4023590ED16E5F1EFF3B1C17629
Fingerprint: 7FB47FA4FDFDE2A3A04392FA22634C44DF38A4023590ED16E5F1EFF3B1C17629
Certificate finger print: 7F:B4:7F:A4:FD:FD:E2:A3:A0:43:92:FA:22:63:4C:44:DF:38:A4:02:35:90:ED:16:E5:F1:EF:F3:B1:C1:76:29
Fingerprint: 8DD764589E21B6E399FF5244D74CFA172981F6F09B37B804338C64893B56EC84
Server certificate hash: 8D:D7:64:58:9E:21:B6:E3:99:FF:52:44:D7:4C:FA:17:29:81:F6:F0:9B:37:B8:04:33:8C:64:89:3B:56:EC:84
server listening ip:127.0.0.1:4433
Data datagram received: 1200
2
📥 Server received packet level=EncryptionLevel.initial len=217
✅ Server Initial keys ready
  initialRead : QuicKeys{
  key: b14b918124fda5c8d79847602fa3520b;
  iv:  ddbc15dea80925a55686a7df;
  hp:  6df4e9d737cdf714711d7c617ee82981;
}
  initialWrite: QuicKeys{
  key: d77fc4056fcfa32bd1302469ee6ebf90;
  iv:  fcb748e37ff79860faa07477;
  hp:  440b2725e91dc79b370711ef792faa3d;
}
  clientOrigDcid: 0001020304050607
  peerScid      : 984a36172ac5caff
  localCid      : 6c75180cead5453d
--- decryptQuicPacket keys ---
READ.key = b14b918124fda5c8d79847602fa3520b
READ.iv  = ddbc15dea80925a55686a7df
READ.hp  = 6df4e9d737cdf714711d7c617ee82981
dcid     = 0001020304050607
pkt[0]   = 0xc2
pkt.len  = 217
Unmasked first byte: 0xc0
Packet number offset: 26
Packet number length: 1
Packet number: 0
Nonce: ddbc15dea80925a55686a7df
AAD (hex): c00000000108000102030405060708984a36172ac5caff0040bf00
Ciphertext+Tag len: 190
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 060040aa010000a60303052a485fb42d
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed CRYPTO frame offset=0 len=170
✅ Server has full ClientHello
✅ Client offered ALPNs: []
✅ Server selected ALPN: quic-echo-example
✅ Server handshake keys ready
  handshakeRead : QuicKeys{
  key: e1e0ec05ff7adf2cba42c590e353369f;
  iv:  2254926e48f7e1826bdb7700;
  hp:  fd4b250b1c154962465a5ea2ca2a98e8;
}
  handshakeWrite: QuicKeys{
  key: edb051a2c5a555ebc1b19d0b222b38cf;
  iv:  0a33b78a413e5bd01196f53d;
  hp:  2d19f6b90c00f585eee543f418644955;
}
✅ Server handshake artifacts stored
  encryptedExtensions: 96 bytes
  certificate        : 296 bytes
  certificateVerify  : 79 bytes
✅ Server built Finished verify_data=8e581f897cb59666f9e7f726c2bf72980838ef4679447004e60ea4049f95cd7c
--- encryptQuicPacket keys ---
READ.key = d77fc4056fcfa32bd1302469ee6ebf90
READ.iv  = fcb748e37ff79860faa07477
READ.hp  = 440b2725e91dc79b370711ef792faa3d
dcid     = 984a36172ac5caff
pkt[0]   = 0x06
pkt.len  = 94
✅ Server sent Initial(ServerHello) pn=0 dcid=984a36172ac5caff scid=6c75180cead5453d
--- encryptQuicPacket keys ---
READ.key = edb051a2c5a555ebc1b19d0b222b38cf
READ.iv  = 0a33b78a413e5bd01196f53d
READ.hp  = 2d19f6b90c00f585eee543f418644955
dcid     = 984a36172ac5caff
pkt[0]   = 0x06
pkt.len  = 100
✅ Server sent Handshake pn=1 offset=0 len=96 dcid=984a36172ac5caff scid=6c75180cead5453d  
--- encryptQuicPacket keys ---
READ.key = edb051a2c5a555ebc1b19d0b222b38cf
READ.iv  = 0a33b78a413e5bd01196f53d
READ.hp  = 2d19f6b90c00f585eee543f418644955
dcid     = 984a36172ac5caff
pkt[0]   = 0x06
pkt.len  = 301
✅ Server sent Handshake pn=2 offset=96 len=296 dcid=984a36172ac5caff scid=6c75180cead5453d
--- encryptQuicPacket keys ---
READ.key = edb051a2c5a555ebc1b19d0b222b38cf
READ.iv  = 0a33b78a413e5bd01196f53d
READ.hp  = 2d19f6b90c00f585eee543f418644955
dcid     = 984a36172ac5caff
pkt[0]   = 0x06
pkt.len  = 84
✅ Server sent Handshake pn=3 offset=392 len=79 dcid=984a36172ac5caff scid=6c75180cead5453d
--- encryptQuicPacket keys ---
READ.key = edb051a2c5a555ebc1b19d0b222b38cf
READ.iv  = 0a33b78a413e5bd01196f53d
READ.hp  = 2d19f6b90c00f585eee543f418644955
dcid     = 984a36172ac5caff
pkt[0]   = 0x06
pkt.len  = 40
✅ Server sent Handshake pn=4 offset=471 len=36 dcid=984a36172ac5caff scid=6c75180cead5453d
🎉 Server payload parsing complete.
--- encryptQuicPacket keys ---
READ.key = d77fc4056fcfa32bd1302469ee6ebf90
READ.iv  = fcb748e37ff79860faa07477
READ.hp  = 440b2725e91dc79b370711ef792faa3d
dcid     = 984a36172ac5caff
pkt[0]   = 0x03
pkt.len  = 8
--- encryptQuicPacket keys ---
READ.key = d77fc4056fcfa32bd1302469ee6ebf90
READ.iv  = fcb748e37ff79860faa07477
READ.hp  = 440b2725e91dc79b370711ef792faa3d
dcid     = 984a36172ac5caff
pkt[0]   = 0x03
pkt.len  = 1158
✅ Sent ACK (EncryptionLevel.initial) pn=1 acked=[0]
📥 Server received packet level=EncryptionLevel.application len=983
ℹ️ Ignoring early Application packet (1-RTT keys not ready)
Data datagram received: 1200
2
📥 Server received packet level=EncryptionLevel.initial len=50
--- decryptQuicPacket keys ---
READ.key = b14b918124fda5c8d79847602fa3520b
READ.iv  = ddbc15dea80925a55686a7df
READ.hp  = 6df4e9d737cdf714711d7c617ee82981
dcid     = 0001020304050607
pkt[0]   = 0xc2
pkt.len  = 50
Unmasked first byte: 0xc0
Packet number offset: 25
Packet number length: 1
Packet number: 1
Nonce: ddbc15dea80925a55686a7de
AAD (hex): c000000001086c75180cead5453d08984a36172ac5caff001901
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0300000000000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=0 delay=0 firstRange=0
🎉 Server payload parsing complete.
📥 Server received packet level=EncryptionLevel.application len=1150
ℹ️ Ignoring early Application packet (1-RTT keys not ready)
Data datagram received: 49
1
📥 Server received packet level=EncryptionLevel.handshake len=49
--- decryptQuicPacket keys ---
READ.key = e1e0ec05ff7adf2cba42c590e353369f
READ.iv  = 2254926e48f7e1826bdb7700
READ.hp  = fd4b250b1c154962465a5ea2ca2a98e8
dcid     = 6c75180cead5453d
pkt[0]   = 0xe7
pkt.len  = 49
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 0
Nonce: 2254926e48f7e1826bdb7700
AAD (hex): e000000001086c75180cead5453d08984a36172ac5caff1900
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0301000000000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=1 delay=0 firstRange=0
🎉 Server payload parsing complete.
Data datagram received: 49
1
📥 Server received packet level=EncryptionLevel.handshake len=49
--- decryptQuicPacket keys ---
READ.key = e1e0ec05ff7adf2cba42c590e353369f
READ.iv  = 2254926e48f7e1826bdb7700
READ.hp  = fd4b250b1c154962465a5ea2ca2a98e8
dcid     = 6c75180cead5453d
pkt[0]   = 0xeb
pkt.len  = 49
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 1
Nonce: 2254926e48f7e1826bdb7701
AAD (hex): e000000001086c75180cead5453d08984a36172ac5caff1901
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0302000001000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=2 delay=0 firstRange=1
🎉 Server payload parsing complete.
Data datagram received: 49
1
📥 Server received packet level=EncryptionLevel.handshake len=49
--- decryptQuicPacket keys ---
READ.key = e1e0ec05ff7adf2cba42c590e353369f
READ.iv  = 2254926e48f7e1826bdb7700
READ.hp  = fd4b250b1c154962465a5ea2ca2a98e8
dcid     = 6c75180cead5453d
pkt[0]   = 0xed
pkt.len  = 49
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 2
Nonce: 2254926e48f7e1826bdb7702
AAD (hex): e000000001086c75180cead5453d08984a36172ac5caff1902
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0303000002000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=3 delay=0 firstRange=2
🎉 Server payload parsing complete.
Data datagram received: 49
1
📥 Server received packet level=EncryptionLevel.handshake len=49
--- decryptQuicPacket keys ---
READ.key = e1e0ec05ff7adf2cba42c590e353369f
READ.iv  = 2254926e48f7e1826bdb7700
READ.hp  = fd4b250b1c154962465a5ea2ca2a98e8
dcid     = 6c75180cead5453d
pkt[0]   = 0xec
pkt.len  = 49
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 3
Nonce: 2254926e48f7e1826bdb7703
AAD (hex): e000000001086c75180cead5453d08984a36172ac5caff1903
Ciphertext+Tag len: 24
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0304000003000000
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed ACK largest=4 delay=0 firstRange=3
🎉 Server payload parsing complete.
Data datagram received: 80
1
📥 Server received packet level=EncryptionLevel.handshake len=80
--- decryptQuicPacket keys ---
READ.key = e1e0ec05ff7adf2cba42c590e353369f
READ.iv  = 2254926e48f7e1826bdb7700
READ.hp  = fd4b250b1c154962465a5ea2ca2a98e8
dcid     = 6c75180cead5453d
pkt[0]   = 0xe8
pkt.len  = 80
Unmasked first byte: 0xe0
Packet number offset: 24
Packet number length: 1
Packet number: 4
Nonce: 2254926e48f7e1826bdb7704
AAD (hex): e000000001086c75180cead5453d08984a36172ac5caff3804
Ciphertext+Tag len: 55
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 060024140000206a2e4f5cfd11e9c201
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed CRYPTO frame offset=0 len=36
✅ Server received Client Finished
  expected: 6a2e4f5cfd11e9c2012a769d60797655d16b3ff303f9aadb10d601bcf17a9362
  actual  : 6a2e4f5cfd11e9c2012a769d60797655d16b3ff303f9aadb10d601bcf17a9362
✅ Client Finished verified
✅ Server 1-RTT keys installed
  appRead : QuicKeys{
  key: f302de625ddfe8ca974358b270f463d1;
  iv:  b966ff73fa905e9fc6a549b2;
  hp:  b58d5adc164a4bcf3d443cefdfc93a47;
}
  appWrite: QuicKeys{
  key: 1e83bba17374ea29ecb7db93ce00739d;
  iv:  5ef55e0f9213763086df077b;
  hp:  d9c7e80fd36fad51ee1f34271b84e457;
}
--- encryptQuicPacket keys ---
READ.key = 1e83bba17374ea29ecb7db93ce00739d
READ.iv  = 5ef55e0f9213763086df077b
READ.hp  = d9c7e80fd36fad51ee1f34271b84e457
dcid     = 984a36172ac5caff
pkt[0]   = 0x0a
pkt.len  = 19
✅ Sent application STREAM pn=0 streamId=3 len=16 fin=false
✅ HTTP/3 control stream sent
🎉 Server payload parsing complete.
Data datagram received: 75
1
📥 Server received packet level=EncryptionLevel.application len=75
--- decryptQuicPacket keys ---
READ.key = f302de625ddfe8ca974358b270f463d1
READ.iv  = b966ff73fa905e9fc6a549b2
READ.hp  = b58d5adc164a4bcf3d443cefdfc93a47
dcid     = 6c75180cead5453d
pkt[0]   = 0x4a
pkt.len  = 75
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 0
Nonce: b966ff73fa905e9fc6a549b2
AAD (hex): 406c75180cead5453d00
Ciphertext+Tag len: 65
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 0a002e012c0000cfd750096c6f63616c
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed STREAM streamId=0 offset=0 len=46 fin=false
✅ WebTransport session accepted on stream 0
--- encryptQuicPacket keys ---
READ.key = 1e83bba17374ea29ecb7db93ce00739d
READ.iv  = 5ef55e0f9213763086df077b
READ.hp  = d9c7e80fd36fad51ee1f34271b84e457
dcid     = 984a36172ac5caff
pkt[0]   = 0x0a
pkt.len  = 46
✅ Sent application STREAM pn=1 streamId=0 len=43 fin=false
🎉 Server payload parsing complete.
--- encryptQuicPacket keys ---
READ.key = 1e83bba17374ea29ecb7db93ce00739d
READ.iv  = 5ef55e0f9213763086df077b
READ.hp  = d9c7e80fd36fad51ee1f34271b84e457
dcid     = 984a36172ac5caff
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.application) pn=2 acked=[0]
Data datagram received: 33
1
📥 Server received packet level=EncryptionLevel.application len=33
--- decryptQuicPacket keys ---
READ.key = f302de625ddfe8ca974358b270f463d1
READ.iv  = b966ff73fa905e9fc6a549b2
READ.hp  = b58d5adc164a4bcf3d443cefdfc93a47
dcid     = 6c75180cead5453d
pkt[0]   = 0x5c
pkt.len  = 33
Unmasked first byte: 0x40
Packet number offset: 9
Packet number length: 1
Packet number: 1
Nonce: b966ff73fa905e9fc6a549b3
AAD (hex): 406c75180cead5453d01
Ciphertext+Tag len: 23
Decrypting cipher text ...
✅ Payload decrypted successfully!
✅ Recovered Message (Hex): 31050001020304
--- Parsing Decrypted QUIC Payload (server) ---
✅ Server parsed DATAGRAM len=5
📦 WebTransport datagram session=0 len=4
--- encryptQuicPacket keys ---
READ.key = 1e83bba17374ea29ecb7db93ce00739d
READ.iv  = 5ef55e0f9213763086df077b
READ.hp  = d9c7e80fd36fad51ee1f34271b84e457
dcid     = 984a36172ac5caff
pkt[0]   = 0x31
pkt.len  = 7
✅ Sent WebTransport DATAGRAM pn=3 session=0 len=4
🎉 Server payload parsing complete.
--- encryptQuicPacket keys ---
READ.key = 1e83bba17374ea29ecb7db93ce00739d
READ.iv  = 5ef55e0f9213763086df077b
READ.hp  = d9c7e80fd36fad51ee1f34271b84e457
dcid     = 984a36172ac5caff
pkt[0]   = 0x03
pkt.len  = 8
✅ Sent ACK (EncryptionLevel.application) pn=4 acked=[0, 1]
Copilot said:
Copilot

Reasoning completed in 3 steps
This is much better — the big cryptographic and handshake problems are fixed.
Your logs now show:

✅ dynamic ClientHello is live
✅ handshake keys match
✅ full TLS/QUIC handshake completes
✅ HTTP/3 + WebTransport works end-to-end
But for your specific question:

No — it is still not defaulting to h3 yet
The proof is right here in the server log:




Plain Text
✅ Client offered ALPNs: []
✅ Server selected ALPN: quic-echo-example
So the server is still not seeing h3 from the client, and it is still falling back / defaulting to:




Plain Text
quic-echo-example
The exact reason ALPN is still empty
This is the important subtle bug:

In your builder, you manually add the ALPN extension
You do this:




Plain Text
final alpnProto = Uint8List.fromList(alpns.first.codeUnits);
final alpnBuf = QuicBuffer()
  ..pushUint16(alpnProto.length + 1)
  ..pushUint8(alpnProto.length)
  ..pushBytes(alpnProto);
extensions.add(makeExt(0x0010, alpnBuf));

So far, so good.

But then serialize() calls upsertAlpnExtension()
Inside ClientHello.serialize():




Dart
Uint8List serialize() {
  // Ensure ALPN extension reflects semantic field
  upsertAlpnExtension();
  ...
}
And upsertAlpnExtension() does this:




Dart
final protocols = alpn ?? <String>[];

// Remove ALPN extension if empty
if (protocols.isEmpty) {
  extensions.removeWhere((e) => e.type == 0x0010);
  return;
}
So if alpn is null / empty, serialize() removes the ALPN extension you manually added.

That exactly matches your logs
Client says:




Plain Text
🚨 Dynamic ALPNs: []
``
Server says:




Plain Text
✅ Client offered ALPNs: []
``
So the wire image is being serialized without the ALPN extension.

That is why the server never sees h3.

The precise fix
In buildInitialClientHello(...), set the semantic ALPN field too
When returning ClientHello(...), change this:




Dart
return ClientHello(
  type: 'client_hello',
  legacyVersion: 0x0303,
  random: random,
  sessionId: Uint8List(0),
  cipherSuites: const [0x1301, 0x1302, 0x1303],
  compressionMethods: Uint8List.fromList([0x00]),
  extensions: extensions,
  rawData: Uint8List(0),
);
to this:




Dart
return ClientHello(
  type: 'client_hello',
  legacyVersion: 0x0303,
  random: random,
  sessionId: Uint8List(0),
  cipherSuites: const [0x1301, 0x1302, 0x1303],
  compressionMethods: Uint8List.fromList([0x00]),
  extensions: extensions,
  rawData: Uint8List(0),
  alpn: alpns,
);

That way, when serialize() calls upsertAlpnExtension(), it will keep/replace the ALPN extension correctly instead of deleting it.

Even better cleanup
Since serialize() already knows how to materialize ALPN from alpn, you can simplify the builder:

Recommended approach
Do not manually add extension 0x0010
just set:



Dart
alpn: alpns,

let serialize() insert the ALPN extension
That avoids having two sources of truth.

Why the server still picks quic-echo-example
There are two reasons visible from the behavior:

1) The client is offering no ALPN
So the server cannot select h3.

2) Your server path still falls back to quic-echo-example
The server log proves that even with:




Plain Text
Client offered ALPNs: []
it still proceeds with:




Plain Text
Server selected ALPN: quic-echo-example

So either:

your chooseServerAlpn() is not being enforced in that path, or
the caller to buildServerHandshakeArtifacts(...) is still passing / defaulting:



Dart
alpnProtocol = alpnQuicEchoExample
So yes, the server preference still needs cleanup too if you want strict h3.

What the current run proves is fixed
This is the good news:

The hard handshake bugs are gone
The current run proves that these are now correct:

dynamic ClientHello is used in transcript
CRYPTO frame varint length is accepted
client/server handshake keys match
Finished verify_data matches
1‑RTT keys install correctly
WebTransport CONNECT + DATAGRAM works
That’s a huge milestone.

Remaining issues (now much smaller)
1) ALPN still not actually on the wire
Symptom:



Dart
Dynamic ALPNs: []
Client offered ALPNs: []
Fix:
Set:




Dart
alpn: alpns,

in buildInitialClientHello(...)

2) Server still defaults/falls back to quic-echo-example
Symptom:



Plain Text
Server selected ALPN: quic-echo-example
``
Fix:
Make sure:

supportedAlpnProtocols starts with h3
buildServerHandshakeArtifacts(..., alpnProtocol = alpnH3)
and the actual code path passes the chosen ALPN instead of silently falling back
3) You still have the bogus second packet from padTo1200(rawPacket)
Server still shows:




Plain Text
Data datagram received: 1200
2
📥 Server received packet level=EncryptionLevel.initial len=217
📥 Server received packet level=EncryptionLevel.application len=983
ℹ️ Ignoring early Application packet (1-RTT keys not ready)

That means you are still padding after encryption, which creates an extra fake packet in the UDP datagram.

Proper fix:
Pad the payload before encryption with QUIC 0x00 PADDING frame bytes until the encrypted Initial reaches 1200 bytes.

This is not blocking your current permissive server, but it is still a wire-format cleanup you should do.

Bottom line
Status right now:
✅ dynamic handshake works
✅ WebTransport works
❌ ALPN is still empty on the wire
❌ server is still falling back to quic-echo-example
⚠️ Initial padding still creates a bogus second packet
What to change next
Client-side
In buildInitialClientHello(...), add:




Dart
alpn: alpns,
and ideally stop manually adding extension 0x0010.

Server-side
Make sure the path that builds the handshake artifacts actually uses:




Dart
alpnProtocol = alpnH3
``
or the result of:




Dart
chooseServerAlpn(clientOffered)
``
rather than silently defaulting to quic-echo-example.

My verdict
Cryptographically: success
Protocol-wise: almost there
ALPN-wise: not fixed yet
So the answer to “how about now?” is:

Handshake/WebTransport: yes, working.
Default h3: not yet, because your ClientHello is still serializing without ALPN, and the server is still falling back to quic-echo-example.

If you want, I can give you the exact one-line client fix and the exact one-line server fix next, without any extra theory.









Show me the one-line client fix

Show me the one-line server fix

How to pad payload before encryption?
Message Copilot


AI-generated content may be incorrect
