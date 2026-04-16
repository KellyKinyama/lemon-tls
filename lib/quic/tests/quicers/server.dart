class QuicServer {
  void handleInitial(Uint8List packet) {
    final decrypted = decryptQuicPacket(packet, EncryptionLevel.initial);

    for (final frame in parseFrames(decrypted.plaintext!)) {
      if (frame is CryptoFrame) {
        handleClientHello(frame.data);
      }
    }
  }

  void handleClientHello(Uint8List clientHello) {
    final serverHello = buildServerHello();

    deriveHandshakeKeys();

    sendHandshake([
      buildCryptoFrame(serverHello),
      buildCryptoFrame(buildEncryptedExtensions()),
      buildCryptoFrame(buildCertificate()),
      buildCryptoFrame(buildCertificateVerify()),
      buildCryptoFrame(buildFinished()),
    ]);
  }

  void handleHandshake(Uint8List packet) {
    final decrypted = decryptQuicPacket(packet, EncryptionLevel.handshake);
    for (final frame in parseFrames(decrypted.plaintext!)) {
      if (frame is CryptoFrame) {
        verifyClientFinished(frame.data);
        deriveApplicationKeys();
      }
    }
  }
}