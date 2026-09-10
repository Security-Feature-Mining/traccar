package org.traccar.api.security;

import org.traccar.model.User;

import java.util.Date;

// &begin[User_Login]
public class LoginResult {

    private final User user; // &line[User_Management]
    private final Date expiration; // &line[Token_Expiration] 

    public LoginResult(User user) { // &line[User_Management]
        this(user, null); // &line[User_Management]
    }

    public LoginResult(User user, Date expiration) { // &line[User_Management, Token_Expiration]
        this.user = user; // &line[User_Management]
        this.expiration = expiration; // &line[Token_Expiration]
    }

    // &begin[User_Management]
    public User getUser() {
        return user;
    }
    // &end[User_Management]

    // &begin[Token_Expiration]
    public Date getExpiration() {
        return expiration;
    }
    // &end[Token_Expiration]

}
// &end[User_Login]
