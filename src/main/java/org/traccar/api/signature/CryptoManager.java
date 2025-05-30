/*
 * Copyright 2022 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.api.signature;

import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

// &begin[Asymmetric_Key_Cryptography]
@Singleton
public class CryptoManager {

    private final Storage storage; // &line[Key_Storage]

    private PublicKey publicKey;
    private PrivateKey privateKey;

    // &begin[Key_Storage]
    @Inject
    public CryptoManager(Storage storage) {
        this.storage = storage;
    }
    // &end[Key_Storage]
    // &begin[ECDSA_Signature_Signing]
    public byte[] sign(byte[] data) throws GeneralSecurityException, StorageException {
        if (privateKey == null) {
            initializeKeys();
        }
        Signature signature = Signature.getInstance("SHA256withECDSA"); // &line[Sha256_Hashing]
        signature.initSign(privateKey);
        signature.update(data);
        byte[] block = signature.sign();
        byte[] combined = new byte[1 + block.length + data.length];
        combined[0] = (byte) block.length;
        System.arraycopy(block, 0, combined, 1, block.length);
        System.arraycopy(data, 0, combined, 1 + block.length, data.length);
        return combined;
    }
    // &end[ECDSA_Signature_Signing]
    // &begin[ECDSA_Signature_Verification]
    public byte[] verify(byte[] data) throws GeneralSecurityException, StorageException {
        if (publicKey == null) {
            initializeKeys();
        }
        Signature signature = Signature.getInstance("SHA256withECDSA"); // &line[Sha256_Hashing]
        signature.initVerify(publicKey);
        int length = data[0];
        byte[] originalData = new byte[data.length - 1 - length];
        System.arraycopy(data, 1 + length, originalData, 0, originalData.length);
        signature.update(originalData);
        if (!signature.verify(data, 1, length)) {
            throw new SecurityException("Invalid signature");
        }
        return originalData;
    }
    // &end[ECDSA_Signature_Verification]

// &begin[Key_Generation]
    private void initializeKeys() throws StorageException, GeneralSecurityException {
        KeystoreModel model = storage.getObject(KeystoreModel.class, new Request(new Columns.All())); // &line[Key_Storage]
        if (model != null) {
            // &begin[X509_Key_Generation]
            publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(model.getPublicKey()));
            // &end[X509_Key_Generation]
            // &begin[PKCS8_Key_Generation]
            privateKey = KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(model.getPrivateKey()));
            // &end[PKCS8_Key_Generation]
        } else {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom()); // &line[Secure_Random]
            KeyPair pair = generator.generateKeyPair();

            publicKey = pair.getPublic();
            privateKey = pair.getPrivate();

            // &begin[Key_Storage]
            model = new KeystoreModel();
            model.setPublicKey(publicKey.getEncoded());
            model.setPrivateKey(privateKey.getEncoded());
            storage.addObject(model, new Request(new Columns.Exclude("id")));
            // &end[Key_Storage]
        }
    }
// &end[Key_Generation]
}
// &end[Asymmetric_Key_Cryptography]
