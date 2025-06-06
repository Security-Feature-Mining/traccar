package org.traccar.api.security;

import org.traccar.model.User;

import java.util.Date;

public class LoginResult {

    private final User user;
    private final Date expiration; // &line[Token_Expiration] 

    public LoginResult(User user) {
        this(user, null);
    }

    public LoginResult(User user, Date expiration) {
        this.user = user;
        this.expiration = expiration; // &line[Token_Expiration]
    }

    public User getUser() {
        return user;
    }

    // &begin[Token_Expiration]
    public Date getExpiration() {
        return expiration;
    }
    // &end[Token_Expiration]

}
