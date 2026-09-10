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
package org.traccar.api.security;

import com.google.inject.servlet.RequestScoped;
import org.traccar.model.BaseModel;
import org.traccar.model.Calendar;
import org.traccar.model.Command;
import org.traccar.model.Device;
import org.traccar.model.Group;
import org.traccar.model.GroupedModel;
import org.traccar.model.ManagedUser;
import org.traccar.model.Notification;
import org.traccar.model.Schedulable;
import org.traccar.model.Server;
import org.traccar.model.User;
import org.traccar.model.UserRestrictions;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import java.util.Objects;

// &begin[Permission_Definition]
@RequestScoped
public class PermissionsService {

    private final Storage storage;

    private Server server;
    private User user; // &line[User_Management]

    @Inject
    public PermissionsService(Storage storage) {
        this.storage = storage;
    }

    public Server getServer() throws StorageException {
        if (server == null) {
            server = storage.getObject(
                    Server.class, new Request(new Columns.All()));
        }
        return server;
    }

    // &begin[User_Management]
    public User getUser(long userId) throws StorageException {
        if (user == null && userId > 0) {
            if (userId == ServiceAccountUser.ID) {
                user = new ServiceAccountUser();
            } else {
                user = storage.getObject(
                        User.class, new Request(new Columns.All(), new Condition.Equals("id", userId)));
            }
        }
        return user;
    }
    // &end[User_Management]

    // &begin[Role_Check]
    public boolean notAdmin(long userId) throws StorageException {
        return !getUser(userId).getAdministrator(); // &line[User_Management]
    }

    public void checkAdmin(long userId) throws StorageException, SecurityException {
        if (!getUser(userId).getAdministrator()) { // &line[User_Management]
            throw new SecurityException("Administrator access required"); // &line[SecurityException]
        }
    }

    public void checkManager(long userId) throws StorageException, SecurityException {
        if (!getUser(userId).getAdministrator() && getUser(userId).getUserLimit() == 0) { // &line[User_Management]
            throw new SecurityException("Manager access required"); // &line[SecurityException]
        }
    }
    // &end[Role_Check]

    // &begin[Permission_Check]
    public interface CheckRestrictionCallback {
        boolean denied(UserRestrictions userRestrictions);
    }

    public void checkRestriction(
            long userId, CheckRestrictionCallback callback) throws StorageException, SecurityException { // &line[SecurityException]
        if (!getUser(userId).getAdministrator() // &line[Role_Check, User_Management]
                && (callback.denied(getServer()) || callback.denied(getUser(userId)))) {
            throw new SecurityException("Operation restricted"); // &line[SecurityException]
        }
    }

    public void checkEdit(
            long userId, Class<?> clazz, boolean addition, boolean skipReadonly)
            throws StorageException, SecurityException { // &line[SecurityException]
        if (!getUser(userId).getAdministrator()) {  // &line[Role_Check, User_Management]
            boolean denied = false;
            if (!skipReadonly && (getServer().getReadonly() || getUser(userId).getReadonly())) { // &line[User_Management]
                denied = true;
            } else if (clazz.equals(Device.class)) {
                denied = getServer().getDeviceReadonly() || getUser(userId).getDeviceReadonly() // &line[User_Management]
                        || addition && getUser(userId).getDeviceLimit() == 0; // &line[User_Management]
                if (!denied && addition && getUser(userId).getDeviceLimit() > 0) { // &line[User_Management]
                    int deviceCount = storage.getObjects(Device.class, new Request(
                            new Columns.Include("id"),
                            new Condition.Permission(User.class, userId, Device.class))).size();
                    denied = deviceCount >= getUser(userId).getDeviceLimit(); // &line[User_Management]
                }
            } else if (clazz.equals(Command.class)) {
                denied = getServer().getLimitCommands() || getUser(userId).getLimitCommands();
            }
            if (denied) {
                throw new SecurityException("Write access denied"); // &line[SecurityException]
            }
        }
    }

    public void checkEdit(
            long userId, BaseModel object, boolean addition, boolean skipReadonly)
            throws StorageException, SecurityException { // &line[SecurityException]
        if (!getUser(userId).getAdministrator()) { // &line[Role_Check, User_Management]
            checkEdit(userId, object.getClass(), addition, skipReadonly);
            if (object instanceof GroupedModel after) {
                if (after.getGroupId() > 0) {
                    GroupedModel before = null;
                    if (!addition) {
                        before = storage.getObject(after.getClass(), new Request(
                                new Columns.Include("groupId"), new Condition.Equals("id", after.getId())));
                    }
                    if (before == null || before.getGroupId() != after.getGroupId()) {
                        checkPermission(Group.class, userId, after.getGroupId());
                    }
                }
            }
            if (object instanceof Schedulable after) {
                if (after.getCalendarId() > 0) {
                    Schedulable before = null;
                    if (!addition) {
                        before = storage.getObject(after.getClass(), new Request(
                                new Columns.Include("calendarId"), new Condition.Equals("id", object.getId())));
                    }
                    if (before == null || before.getCalendarId() != after.getCalendarId()) {
                        checkPermission(Calendar.class, userId, after.getCalendarId());
                    }
                }
            }
            if (object instanceof Notification after) {
                if (after.getCommandId() > 0) {
                    Notification before = null;
                    if (!addition) {
                        before = storage.getObject(after.getClass(), new Request(
                                new Columns.Include("commandId"), new Condition.Equals("id", object.getId())));
                    }
                    if (before == null || before.getCommandId() != after.getCommandId()) {
                        checkPermission(Command.class, userId, after.getCommandId());
                    }
                }
            }
        }
    }

    // &begin[User_Management]
    public void checkUser(long userId, long managedUserId) throws StorageException, SecurityException { // &line[SecurityException]
        if (userId != managedUserId && !getUser(userId).getAdministrator()) { // &line[Role_Check]
            if (!getUser(userId).getManager()
                    || storage.getPermissions(User.class, userId, ManagedUser.class, managedUserId).isEmpty()) {
                throw new SecurityException("User access denied"); // &line[SecurityException]
            }
        }
    }

    public void checkUserUpdate(long userId, User before, User after) throws StorageException, SecurityException { // &line[SecurityException]
        if (before.getAdministrator() != after.getAdministrator() // &line[Role_Check]
                || before.getDeviceLimit() != after.getDeviceLimit()
                || before.getUserLimit() != after.getUserLimit()) {
            checkAdmin(userId); // &line[Role_Check]
        }
        User user = userId > 0 ? getUser(userId) : null;
        if (user != null && user.getExpirationTime() != null
                && !Objects.equals(before.getExpirationTime(), after.getExpirationTime())
                && (after.getExpirationTime() == null
                || user.getExpirationTime().compareTo(after.getExpirationTime()) < 0)) {
            checkAdmin(userId); // &line[Role_Check]
        }
        if (before.getReadonly() != after.getReadonly()
                || before.getDeviceReadonly() != after.getDeviceReadonly()
                || before.getDisabled() != after.getDisabled()
                || before.getLimitCommands() != after.getLimitCommands()
                || before.getDisableReports() != after.getDisableReports()
                || before.getFixedEmail() != after.getFixedEmail()) {
            if (userId == after.getId()) {
                checkAdmin(userId); // &line[Role_Check]
            } else if (after.getId() > 0) {
                checkUser(userId, after.getId());
            } else {
                checkManager(userId);
            }
        }
        if (before.getFixedEmail() && !before.getEmail().equals(after.getEmail())) {
            checkAdmin(userId); // &line[Role_Check]
        }
    }
    // &end[User_Management]

    public <T extends BaseModel> void checkPermission(
            Class<T> clazz, long userId, long objectId) throws StorageException, SecurityException { // &line[SecurityException]
        if (!getUser(userId).getAdministrator() && !(clazz.equals(User.class) && userId == objectId)) { // &line[Role_Check, User_Management]
            var object = storage.getObject(clazz, new Request(
                    new Columns.Include("id"),
                    new Condition.And(
                            new Condition.Equals("id", objectId),
                            new Condition.Permission(
                                    User.class, userId, clazz.equals(User.class) ? ManagedUser.class : clazz)))); // &line[User_Management]
            if (object == null) {
                throw new SecurityException(clazz.getSimpleName() + " access denied"); // &line[SecurityException]
            }
        }
    }
    // &end[Permission_Check]

}
// &end[Permission_Definition]
