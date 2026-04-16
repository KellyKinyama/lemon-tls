import 'dart:typed_data';

import '../../packet/quic_packet.dart';
import '../end_to_end.dart';
import '../enums.dart';

class QuicClient {
  TlsState tlsState = TlsState.idle;

  late QuicTrafficKeys initialWrite;
  late QuicTrafficKeys initialRead;
  late QuicTrafficKeys handshakeWrite;
  late QuicTrafficKeys handshakeRead;
  late QuicTrafficKeys appWrite;
  late QuicTrafficKeys appRead;

  late Uint8List clientCid;
  late Uint8List serverCid;

  void startHandshake() {
    // 1. Build TLS ClientHello
    final clientHello = buildClientHello();

    // 2. Wrap into CRYPTO frame
    final cryptoFrame = buildCryptoFrame(clientHello);

    // 3. Send as Initial packet
    final packet = encryptQuicPacket(
      'initial',
      cryptoFrame,
      initialWrite.key,
      initialWrite.iv,
      initialWrite.hp,
      0,
      serverCid,
      clientCid,
      Uint8List(0),
    );

    send(packet!);
    tlsState = TlsState.sentClientHello;
  }

  void handlePacket(Uint8List packet, EncryptionLevel level) {
    final decrypted = decryptQuicPacket(packet, level);

    for (final frame in parseFrames(decrypted.plaintext!)) {
      if (frame is CryptoFrame) {
        handleTlsBytes(frame.data);
      }
    }
  }

  void handleTlsBytes(Uint8List bytes) {
    if (tlsState == TlsState.sentClientHello) {
      // Contains ServerHello
      processServerHello(bytes);
      deriveHandshakeKeys();
      tlsState = TlsState.receivedServerHello;
    } else if (tlsState == TlsState.receivedServerHello) {
      // Accumulate handshake messages
      if (handshakeComplete(bytes)) {
        verifyServerFinished();
        sendClientFinished();
        deriveApplicationKeys();
        tlsState = TlsState.connected;
      }
    }
  }
}
