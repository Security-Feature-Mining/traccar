/*
 * Copyright 2015 - 2022 Anton Tananaev (anton@traccar.org)
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
package org.traccar.api.resource;

import org.traccar.api.BaseResource;
import org.traccar.api.security.CodeRequiredException;
import org.traccar.api.security.LoginResult;
import org.traccar.api.security.LoginService;
import org.traccar.api.signature.TokenManager;
import org.traccar.database.OpenIdProvider;
import org.traccar.helper.LogAction;
import org.traccar.helper.SessionHelper;
import org.traccar.helper.WebHelper;
import org.traccar.model.User;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import com.nimbusds.oauth2.sdk.ParseException;
import jakarta.annotation.Nullable;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.net.URI;

// &begin[User_Session]
@Path("session")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class SessionResource extends BaseResource {

    // &begin[User_Login]
    @Inject
    private LoginService loginService;
    // &end[User_Login]

    // &begin[OpenID_Authentication]
    @Inject
    @Nullable
    private OpenIdProvider openIdProvider;

    @Inject
    private TokenManager tokenManager;
    // &end[OpenID_Authentication]

    @Context
    private HttpServletRequest request;

    // &begin[User_Authentication]
    @PermitAll
    @GET
    public User get(@QueryParam("token") String token) throws StorageException, IOException, GeneralSecurityException {

        // &begin[Token_Authentication]
        if (token != null) {
            LoginResult loginResult = loginService.login(token);
            if (loginResult != null) {
                User user = loginResult.getUser();
                SessionHelper.userLogin(request, user, loginResult.getExpiration());
                return user;
            }
        }
        // &end[Token_Authentication]

        Long userId = (Long) request.getSession().getAttribute(SessionHelper.USER_ID_KEY);
        if (userId != null) {
            User user = permissionsService.getUser(userId);
            if (user != null) {
                return user;
            }
        }

        throw new WebApplicationException(Response.status(Response.Status.NOT_FOUND).build());
    }
    // &end[User_Authentication]

    @Path("{id}")
    @GET
    public User get(@PathParam("id") long userId) throws StorageException {
        permissionsService.checkUser(getUserId(), userId);
        User user = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", userId)));
        SessionHelper.userLogin(request, user, null); // &line[User_Login]
        return user;
    }

    // &begin[User_Login]
    @PermitAll
    @POST
    public User add(
            @FormParam("email") String email,
            @FormParam("password") String password, // &line[Password]
            @FormParam("code") Integer code) throws StorageException {
        LoginResult loginResult;
        try {
            loginResult = loginService.login(email, password, code); // &line[Password]
        } catch (CodeRequiredException e) {
            Response response = Response
                    .status(Response.Status.UNAUTHORIZED)
                    .header("WWW-Authenticate", "TOTP")
                    .build();
            throw new WebApplicationException(response);
        }
        if (loginResult != null) {
            User user = loginResult.getUser();
            SessionHelper.userLogin(request, user, null);
            return user;
        } else {
            LogAction.failedLogin(WebHelper.retrieveRemoteAddress(request)); // &line[Authentication_Logging]
            throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }
    // &end[User_Login]

    // &begin[User_Logout]
    @DELETE
    public Response remove() {
        LogAction.logout(getUserId(), WebHelper.retrieveRemoteAddress(request)); // &line[Authentication_Logging]
        request.getSession().removeAttribute(SessionHelper.USER_ID_KEY);
        return Response.noContent().build();
    }
    // &end[User_Logout]
    // &begin[Token_Expiration]
    @Path("token")
    @POST
    public String requestToken(
            @FormParam("expiration") Date expiration) throws StorageException, GeneralSecurityException, IOException {
        Date currentExpiration = (Date) request.getSession().getAttribute(SessionHelper.EXPIRATION_KEY);
        if (currentExpiration != null && currentExpiration.before(expiration)) {
            expiration = currentExpiration;
        }
        // &end[Token_Expiration]
        return tokenManager.generateToken(getUserId(), expiration); // &line[Token_Generation] 
    }
    // &begin[OpenID_Authentication]
    @PermitAll
    @Path("openid/auth")
    @GET
    public Response openIdAuth() {
        return Response.seeOther(openIdProvider.createAuthUri()).build();
    }

    // &begin[Token_Generation]
    @PermitAll
    @Path("openid/callback")
    @GET
    public Response requestToken() throws IOException, StorageException, ParseException, GeneralSecurityException {
        StringBuilder requestUrl = new StringBuilder(request.getRequestURL().toString());
        String queryString = request.getQueryString();
        String requestUri = requestUrl.append('?').append(queryString).toString();

        return Response.seeOther(openIdProvider.handleCallback(URI.create(requestUri), request)).build();
    }
    // &end[Token_Generation]
    // &end[OpenID_Authentication]
}
// &end[User_Session]
