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
package org.traccar.api.security;

import org.traccar.model.User;

public class ServiceAccountUser extends User {

    public static final long ID = 9000000000000000000L;

    public ServiceAccountUser() {
        setId(ID);
        setName("Service Account");
        setEmail("none");
        setAdministrator(true); // &line[Role_Assignment] 
    }
}
