/*
 * Copyright 2022 - 2023 Anton Tananaev (anton@traccar.org)
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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.traccar.storage.StorageException;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Singleton
// &begin[Token_Management]
public class TokenManager {

    private static final int DEFAULT_EXPIRATION_DAYS = 7; // &line[Token_Expiration]

    private final ObjectMapper objectMapper;
    private final CryptoManager cryptoManager;

    public static class TokenData {
        // &begin[User]
        @JsonProperty("u")
        private long userId;
        // &end[User]
        // &begin[Token_Expiration]
        @JsonProperty("e")
        private Date expiration;
        // &end[Token_Expiration]
        // &begin[User]
        public long getUserId() {
            return userId;
        }
        // &end[User]
        // &begin[Token_Expiration]
        public Date getExpiration() {
            return expiration;
        }
        // &end[Token_Expiration]
    }

    @Inject
    public TokenManager(ObjectMapper objectMapper, CryptoManager cryptoManager) {
        this.objectMapper = objectMapper;
        this.cryptoManager = cryptoManager;
    }
    // &begin[Token_Generation]
    public String generateToken(long userId) throws IOException, GeneralSecurityException, StorageException {
        return generateToken(userId, null);
    }

    public String generateToken(
            long userId, Date expiration) throws IOException, GeneralSecurityException, StorageException {
        TokenData data = new TokenData();
        data.userId = userId;
        // &begin[Token_Expiration]
        if (expiration != null) {
            data.expiration = expiration;
        } else {
            data.expiration = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(DEFAULT_EXPIRATION_DAYS));
        }
        // &end[Token_Expiration]
        byte[] encoded = objectMapper.writeValueAsBytes(data);
        return Base64.encodeBase64URLSafeString(cryptoManager.sign(encoded));
    }
    // &end[Token_Generation]

// &begin[Token_Validation]
    public TokenData verifyToken(String token) throws IOException, GeneralSecurityException, StorageException {
        byte[] encoded = cryptoManager.verify(Base64.decodeBase64(token));
        TokenData data = objectMapper.readValue(encoded, TokenData.class);
        // &begin[Token_Expiration]
        if (data.expiration.before(new Date())) {
            throw new SecurityException("Token has expired");
        }
        // &end[Token_Expiration]
        return data;
    }
// &end[Token_Validation]
}
// &begin[Token_Management]