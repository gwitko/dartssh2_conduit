import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

void main() {
  final rsaPrivate = fixture('ssh-rsa/id_rsa');
  final rsaPrivateOpenSSH = fixture('ssh-rsa/id_rsa.openssh');

  final rsaPrivateEncrypted = fixture('ssh-rsa-passphrase/id_rsa');
  final rsaPassphrase = fixture('ssh-rsa-passphrase/passphrase');

  final ecdsaNistP256Private = fixture('ecdsa-sha2-nistp256/id_ecdsa');
  final ecdsaNistP384Private = fixture('ecdsa-sha2-nistp384/id_ecdsa');
  final ecdsaNistP521Private = fixture('ecdsa-sha2-nistp521/id_ecdsa');

  final ed25519Private = fixture('ssh-ed25519/id_ed25519');
  final ed25519PrivateEncrypted = fixture('ssh-ed25519-passphrase/id_ed25519');
  final ed25519PrivatePassphrase = fixture('ssh-ed25519-passphrase/passphrase');

  const legacyEcPrivateKey = '''-----BEGIN EC PRIVATE KEY-----
MIIBaAIBAQQg7TXJD04t4e/CrwIdaxF1FJ+PSF0kTzMQs5TOp9L0MvKggfowgfcC
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////
MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE
axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W
K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8
YyVRAgEBoUQDQgAEQ3EUZAOS4yK43BKX5gl1BPUWPN3CsU0xrptfxnItUD34jPc0
ybMM3pZ6HeBa89ariwVsl/wCYzZfgR64JAC1nQ==
-----END EC PRIVATE KEY-----''';

  const legacyEcPublicKey =
      'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBENxFGQDkuMiuNwSl+YJdQT1FjzdwrFNMa6bX8ZyLVA9+Iz3NMmzDN6Weh3gWvPWq4sFbJf8AmM2X4EeuCQAtZ0= ecdsa 256-083024';

  final legacyEcPrivateKeyWithoutPublic = () {
    final pem = SSHPem.decode(legacyEcPrivateKey);
    final sequence = ASN1Parser(pem.content).nextObject() as ASN1Sequence;
    final stripped = ASN1Sequence();
    for (final element in sequence.elements) {
      if (element.tag != 0xA1) {
        stripped.add(element);
      }
    }
    return SSHPem('EC PRIVATE KEY', {}, stripped.encodedBytes).encode(64);
  }();

  final legacyEcPrivateKeyEncrypted = () {
    final lines = legacyEcPrivateKey.trim().split('\n');
    final body = lines.sublist(1, lines.length - 1).join('\n');
    return '''-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,74E0BC77BE064544

$body
-----END EC PRIVATE KEY-----''';
  }();

  const malformedEcPrivateKey = '''-----BEGIN EC PRIVATE KEY-----
MAA=
-----END EC PRIVATE KEY-----''';

  test('SSHKeyPair.fromPem works with RSA private key', () async {
    final pem = rsaPrivate;
    final keypair = SSHKeyPair.fromPem(pem);
    expect(keypair.length, 1);
    expect(keypair.single, isA<RsaPrivateKey>());
  });

  test('SSHCallbackKeyPair supports asynchronous signing', () async {
    final softwareKey = SSHKeyPair.fromPem(ed25519Private).single;
    final keypair = SSHCallbackKeyPair(
      name: softwareKey.name,
      type: softwareKey.type,
      publicKey: softwareKey.toPublicKey(),
      signer: (data) async {
        await Future<void>.delayed(Duration.zero);
        return softwareKey.sign(data);
      },
    );

    final signature = await keypair.signAsync(
      Uint8List.fromList('sign-me'.codeUnits),
    );

    expect(signature, isA<SSHSignature>());
    expect(keypair.toPublicKey().encode(), softwareKey.toPublicKey().encode());
    expect(
      () => keypair.sign(Uint8List.fromList('sign-me'.codeUnits)),
      throwsUnsupportedError,
    );
  });

  test('OpenSSHKeyPair.toEncryptedPem round-trips through fromPem', () {
    final original = SSHKeyPair.fromPem(ed25519Private).single as OpenSSHKeyPair;

    final pem = original.toEncryptedPem('round trip pass');

    expect(SSHKeyPair.isEncryptedPem(pem), isTrue);

    final decrypted = SSHKeyPair.fromPem(pem, 'round trip pass').single;
    expect(
      decrypted.toPublicKey().encode(),
      original.toPublicKey().encode(),
    );
  });

  test('OpenSSHKeyPair.toEncryptedPem rejects the wrong passphrase', () {
    final original = SSHKeyPair.fromPem(ed25519Private).single as OpenSSHKeyPair;

    final pem = original.toEncryptedPem('right');

    expect(() => SSHKeyPair.fromPem(pem, 'wrong'), throwsA(anything));
  });

  test('OpenSSHKeyPair.toEncryptedPem with empty passphrase is unencrypted', () {
    final original = SSHKeyPair.fromPem(ed25519Private).single as OpenSSHKeyPair;

    final pem = original.toEncryptedPem('');

    expect(SSHKeyPair.isEncryptedPem(pem), isFalse);
  });

  test('SSHKeyPair.fromPem works with OpenSSH ECDSA security key stubs', () {
    final keypair = SSHKeyPair.fromPem(_securityKeyEcdsaPem).single;

    expect(keypair, isA<OpenSSHSecurityKeyEcdsaKeyPair>());
    final securityKey = keypair as OpenSSHSecurityKeyEcdsaKeyPair;
    expect(securityKey.application, 'ssh:');
    expect(securityKey.flags, 1);
    expect(securityKey.keyHandle, Uint8List.fromList([9, 8, 7]));
    expect(
      SSHSecurityKeyEcdsaPublicKey.decode(securityKey.toPublicKey().encode())
          .application,
      'ssh:',
    );
    expect(() => securityKey.sign(Uint8List(0)), throwsUnsupportedError);
  });

  test('SSHKeyPair.fromPem works with OpenSSH Ed25519 security key stubs', () {
    final keypair = SSHKeyPair.fromPem(_securityKeyEd25519Pem).single;

    expect(keypair, isA<OpenSSHSecurityKeyEd25519KeyPair>());
    final securityKey = keypair as OpenSSHSecurityKeyEd25519KeyPair;
    expect(securityKey.application, 'ssh:');
    expect(securityKey.flags, 1);
    expect(securityKey.keyHandle, Uint8List.fromList([1, 2, 3]));
    expect(
      SSHSecurityKeyEd25519PublicKey.decode(securityKey.toPublicKey().encode())
          .application,
      'ssh:',
    );
    expect(() => securityKey.sign(Uint8List(0)), throwsUnsupportedError);
  });

  test('security key signatures round-trip through SSH encoding', () {
    final ecdsa = SSHSecurityKeyEcdsaSignature(
      r: BigInt.from(11),
      s: BigInt.from(22),
      flags: 1,
      counter: 7,
    );
    final decodedEcdsa = SSHSecurityKeyEcdsaSignature.decode(ecdsa.encode());
    expect(decodedEcdsa.r, ecdsa.r);
    expect(decodedEcdsa.s, ecdsa.s);
    expect(decodedEcdsa.flags, 1);
    expect(decodedEcdsa.counter, 7);

    final ed25519 = SSHSecurityKeyEd25519Signature(
      signature: Uint8List.fromList(List<int>.filled(64, 42)),
      flags: 1,
      counter: 8,
    );
    final decodedEd25519 = SSHSecurityKeyEd25519Signature.decode(
      ed25519.encode(),
    );
    expect(decodedEd25519.signature, ed25519.signature);
    expect(decodedEd25519.flags, 1);
    expect(decodedEd25519.counter, 8);
  });

  test('SSHKeyPair.fromPem works with ECdSA private key', () async {
    final pem = ecdsaNistP256Private;
    final keypair = SSHKeyPair.fromPem(pem);
    expect(keypair.length, 1);
    expect(keypair.single, isA<OpenSSHEcdsaKeyPair>());
  });

  test('SSHKeyPair.fromPem works with ECDSA nistp384 private key', () async {
    final pem = ecdsaNistP384Private;
    final keypairs = SSHKeyPair.fromPem(pem);

    expect(keypairs.length, 1);
    final keypair = keypairs.single as OpenSSHEcdsaKeyPair;
    expect(keypair.curveId, 'nistp384');
  });

  test('SSHKeyPair.fromPem works with ECDSA nistp521 private key', () async {
    final pem = ecdsaNistP521Private;
    final keypairs = SSHKeyPair.fromPem(pem);

    expect(keypairs.length, 1);
    final keypair = keypairs.single as OpenSSHEcdsaKeyPair;
    expect(keypair.curveId, 'nistp521');
  });

  test('SSHKeyPair.fromPem works with Ed25519 private key', () async {
    final pem = ed25519Private;
    final keypairs = SSHKeyPair.fromPem(pem);
    expect(keypairs.length, 1);
    expect(keypairs.single, isA<OpenSSHEd25519KeyPair>());
  });

  test('SSHKeyPair.fromPem works with legacy EC PRIVATE KEY format', () async {
    final keypairs = SSHKeyPair.fromPem(legacyEcPrivateKey);
    expect(keypairs.length, 1);
    final keypair = keypairs.single as OpenSSHEcdsaKeyPair;

    expect(keypair.curveId, 'nistp256');

    final publicBlob = base64.decode(legacyEcPublicKey.split(' ')[1]);
    final publicKey = SSHEcdsaPublicKey.decode(Uint8List.fromList(publicBlob));

    expect(keypair.q, publicKey.q);
  });

  test(
    'SSHKeyPair.fromPem works with legacy EC PRIVATE KEY without embedded public key',
    () async {
      final keypairs = SSHKeyPair.fromPem(legacyEcPrivateKeyWithoutPublic);
      expect(keypairs.length, 1);
      final keypair = keypairs.single as OpenSSHEcdsaKeyPair;

      final publicBlob = base64.decode(legacyEcPublicKey.split(' ')[1]);
      final publicKey = SSHEcdsaPublicKey.decode(
        Uint8List.fromList(publicBlob),
      );

      expect(keypair.curveId, 'nistp256');
      expect(keypair.q, publicKey.q);
    },
  );

  test(
    'SSHKeyPair.fromPem rejects passphrase for unencrypted EC PRIVATE KEY',
    () {
      expect(
        () => SSHKeyPair.fromPem(legacyEcPrivateKey, 'test'),
        throwsArgumentError,
      );
    },
  );

  test('SSHKeyPair.isEncryptedPem detects encrypted EC PRIVATE KEY', () {
    expect(SSHKeyPair.isEncryptedPem(legacyEcPrivateKeyEncrypted), isTrue);
  });

  test('SSHKeyPair.fromPem rejects encrypted EC PRIVATE KEY for now', () {
    expect(
      () => SSHKeyPair.fromPem(legacyEcPrivateKeyEncrypted),
      throwsA(isA<UnsupportedError>()),
    );
  });

  test(
    'SSHKeyPair.fromPem throws decode error on malformed EC PRIVATE KEY',
    () {
      expect(
        () => SSHKeyPair.fromPem(malformedEcPrivateKey),
        throwsA(isA<SSHKeyDecodeError>()),
      );
    },
  );

  test('SSHKeyPair.isEncryptedPem works with RSA private key', () async {
    final pem = rsaPrivate;
    final pemEncrypted = rsaPrivateEncrypted;
    expect(SSHKeyPair.isEncryptedPem(pem), false);
    expect(SSHKeyPair.isEncryptedPem(pemEncrypted), true);
  });

  test('SSHKeyPair.isEncryptedPem works with ed25519 private key', () async {
    final pem = ed25519Private;
    final pemEncrypted = ed25519PrivateEncrypted;
    expect(SSHKeyPair.isEncryptedPem(pem), false);
    expect(SSHKeyPair.isEncryptedPem(pemEncrypted), true);
  });

  test('SSHKeyPair.fromPem can decrypt RSA private key', () async {
    final pem = rsaPrivateEncrypted;
    final passphrase = rsaPassphrase;
    final keypair = SSHKeyPair.fromPem(pem, passphrase);
    expect(keypair.length, 1);
    expect(keypair.single, isA<RsaPrivateKey>());
    expect(keypair.single.toPem(), rsaPrivate);
  });

  test('SSHKeyPair.fromPem can decrypt ed25519 private key', () async {
    final pem = ed25519PrivateEncrypted;
    final passphrase = ed25519PrivatePassphrase;
    final keypairs = SSHKeyPair.fromPem(pem, passphrase);
    expect(keypairs.length, 1);
    expect(keypairs.single, isA<OpenSSHEd25519KeyPair>());
  });

  test('SSHKeyPair.fromPem with wrong passphrase throws on RSA key', () async {
    final pem = rsaPrivateEncrypted;
    final passphrase = 'wrong';
    expect(
      () => SSHKeyPair.fromPem(pem, passphrase),
      throwsA(isA<SSHKeyDecodeError>()),
    );
  });

  test('SSHKeyPair.fromPem with wrong passphrase throws on ed25519', () async {
    final pem = ed25519PrivateEncrypted;
    final passphrase = 'wrong';
    expect(
      () => SSHKeyPair.fromPem(pem, passphrase),
      throwsA(isA<SSHKeyDecodeError>()),
    );
  });

  test('RsaPrivateKey.toPem() works', () async {
    final pem = rsaPrivate;
    final keypair = SSHKeyPair.fromPem(pem).single;
    expect(keypair.toPem(), pem);
  });

  test('OpenSSHRsaKeyPair.toPem() works', () async {
    final pem1 = rsaPrivateOpenSSH;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHRsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHRsaKeyPair;

    expect(pem1.length, pem2.length);

    final dataToSign = Uint8List.fromList('random-data-to-sign'.codeUnits);
    final signature1 = keypair1.sign(dataToSign);
    final signature2 = keypair2.sign(dataToSign);

    expect(signature1.type, signature2.type);
    expect(signature1.signature, signature2.signature);
  });

  test('OpenSSHEcdsaKeyPair.toPem() works', () async {
    final pem1 = ecdsaNistP256Private;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEcdsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEcdsaKeyPair;

    expect(pem1.length, pem2.length);

    expect(keypair1.curveId, keypair2.curveId);
    expect(keypair1.d, keypair2.d);
    expect(keypair1.q, keypair2.q);
  });

  test('OpenSSHEcdsaKeyPair.toPem() works for nistp384', () async {
    final pem1 = ecdsaNistP384Private;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEcdsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEcdsaKeyPair;

    expect(keypair1.curveId, keypair2.curveId);
    expect(keypair1.d, keypair2.d);
    expect(keypair1.q, keypair2.q);
  });

  test('OpenSSHEcdsaKeyPair.toPem() works for nistp521', () async {
    final pem1 = ecdsaNistP521Private;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEcdsaKeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEcdsaKeyPair;

    expect(keypair1.curveId, keypair2.curveId);
    expect(keypair1.d, keypair2.d);
    expect(keypair1.q, keypair2.q);
  });

  test('OpenSSHEd25519KeyPair.toPem() works', () async {
    final pem1 = ed25519Private;
    final keypair1 = SSHKeyPair.fromPem(pem1).single as OpenSSHEd25519KeyPair;

    final pem2 = keypair1.toPem();
    final keypair2 = SSHKeyPair.fromPem(pem2).single as OpenSSHEd25519KeyPair;

    expect(pem1.length, pem2.length);

    final dataToSign = Uint8List.fromList('random-data-to-sign'.codeUnits);
    final signature1 = keypair1.sign(dataToSign);
    final signature2 = keypair2.sign(dataToSign);

    expect(signature1.signature, signature2.signature);
  });
}

final _securityKeyEcdsaPem = () {
  final q = Uint8List.fromList([4, ...List<int>.generate(64, (i) => i + 1)]);
  final privateWriter = SSHMessageWriter()
    ..writeUint32(0x12345678)
    ..writeUint32(0x12345678)
    ..writeUtf8(SSHSecurityKeyEcdsaPublicKey.type)
    ..writeUtf8(SSHSecurityKeyEcdsaPublicKey.curveId)
    ..writeString(q)
    ..writeUtf8('ssh:')
    ..writeUint8(1)
    ..writeString(Uint8List.fromList([9, 8, 7]))
    ..writeUtf8('');
  while (privateWriter.length % 8 != 0) {
    privateWriter.writeUint8(privateWriter.length % 8);
  }
  return OpenSSHKeyPairs.unencrypted(
    publicKeys: [
      SSHSecurityKeyEcdsaPublicKey(q: q, application: 'ssh:').encode(),
    ],
    privateKeyBlob: privateWriter.takeBytes(),
  ).toPem();
}();

final _securityKeyEd25519Pem = () {
  final publicKey = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
  final privateWriter = SSHMessageWriter()
    ..writeUint32(0x12345678)
    ..writeUint32(0x12345678)
    ..writeUtf8(SSHSecurityKeyEd25519PublicKey.type)
    ..writeString(publicKey)
    ..writeUtf8('ssh:')
    ..writeUint8(1)
    ..writeString(Uint8List.fromList([1, 2, 3]))
    ..writeUtf8('');
  while (privateWriter.length % 8 != 0) {
    privateWriter.writeUint8(privateWriter.length % 8);
  }
  return OpenSSHKeyPairs.unencrypted(
    publicKeys: [
      SSHSecurityKeyEd25519PublicKey(
        key: publicKey,
        application: 'ssh:',
      ).encode(),
    ],
    privateKeyBlob: privateWriter.takeBytes(),
  ).toPem();
}();
