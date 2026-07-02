import 'dart:typed_data';

import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:test/test.dart';

void main() {
  group('SSH_Message_Userauth_Request.publicKey', () {
    test('encodes a probe without a signature', () {
      final message = SSH_Message_Userauth_Request.publicKey(
        username: 'root',
        publicKeyAlgorithm: 'sk-ssh-ed25519@openssh.com',
        publicKey: Uint8List.fromList([1, 2, 3]),
        signature: null,
      );

      final bytes = message.encode();
      final decoded = SSH_Message_Userauth_Request.decode(bytes);

      expect(decoded.methodName, 'publickey');
      expect(decoded.publicKeyAlgorithm, 'sk-ssh-ed25519@openssh.com');
      expect(decoded.publicKey, [1, 2, 3]);
    });
  });

  group('SSH_Message_Userauth_PublicKey_Ok', () {
    test('round-trips through encode and decode', () {
      final message = SSH_Message_Userauth_PublicKey_Ok(
        publicKeyAlgorithm: 'sk-ssh-ed25519@openssh.com',
        publicKey: Uint8List.fromList([4, 5, 6, 7]),
      );

      final decoded = SSH_Message_Userauth_PublicKey_Ok.decode(
        message.encode(),
      );

      expect(decoded.publicKeyAlgorithm, 'sk-ssh-ed25519@openssh.com');
      expect(decoded.publicKey, [4, 5, 6, 7]);
    });
  });
}
