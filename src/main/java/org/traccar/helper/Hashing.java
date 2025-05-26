/*
 * Copyright 2015 Anton Tananaev (anton@traccar.org)
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
package org.traccar.helper;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

// &begin[Sha1_Hashing]
public final class Hashing {

    public static final int ITERATIONS = 1000;
    public static final int SALT_SIZE = 24; // &line[Salting] 
    public static final int HASH_SIZE = 24;
    // &begin[PBKDF2_Key_Generation]
    private static SecretKeyFactory factory;
    static {
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    // &end[PBKDF2_Key_Generation]

    public static class HashingResult {

        private final String hash;
        private final String salt; // &line[Salting] 

        public HashingResult(String hash, String salt) {
            this.hash = hash;
            this.salt = salt; // &line[Salting] 
        }

        public String getHash() {
            return hash;
        }

        // &begin[Salting]
        public String getSalt() {
            return salt;
        }
        // &end[Salting]
    }

    private Hashing() {
    }

    private static byte[] function(char[] password, byte[] salt) { // &line[Salting, Password] 
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, HASH_SIZE * Byte.SIZE); // &line[Salting] 
            return factory.generateSecret(spec).getEncoded();  // &line[PBKDF2_Key_Generation]
        } catch (InvalidKeySpecException e) {
            throw new SecurityException(e);
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom(); // &line[Secure_Random]

    public static HashingResult createHash(String password) { // &line[Password] 
        // &begin[Salting]
        byte[] salt = new byte[SALT_SIZE];
        RANDOM.nextBytes(salt);  // &line[Secure_Random]
        byte[] hash = function(password.toCharArray(), salt); // &line[Password] 
        // &end[Salting]
        return new HashingResult(
                DataConverter.printHex(hash),
                DataConverter.printHex(salt)); // &line[Salting] 
    }

    // &begin[Password_Validation]
    public static boolean validatePassword(String password, String hashHex, String saltHex) { // &line[Salting]
        byte[] hash = DataConverter.parseHex(hashHex);
        // &begin[Salting]
        byte[] salt = DataConverter.parseHex(saltHex);
        return slowEquals(hash, function(password.toCharArray(), salt));
        // &end[Salting]
    }

    /**
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line
     * system using a timing attack and then attacked off-line.
     */
    private static boolean slowEquals(byte[] a, byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
// &end[Password_Validation]
}
// &end[Sha1_Hashing]
