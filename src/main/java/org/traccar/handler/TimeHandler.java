/*
 * Copyright 2019 - 2024 Anton Tananaev (anton@traccar.org)
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
package org.traccar.handler;

import jakarta.inject.Inject;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.Position;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class TimeHandler extends BasePositionHandler {

    private final boolean useServerTime; // &line[Server_Time] 
    private final Set<String> protocols;

    // &begin[Server_Time]
    @Inject
    public TimeHandler(Config config) {
        useServerTime = config.getString(Keys.TIME_OVERRIDE).equalsIgnoreCase("serverTime");
        String protocolList = config.getString(Keys.TIME_PROTOCOLS);
        if (protocolList != null) {
            protocols = new HashSet<>(Arrays.asList(protocolList.split("[, ]")));
        } else {
            protocols = null;
        }
    }
    // &end[Server_Time]

    @Override
    public void onPosition(Position position, Callback callback) {

        if (protocols == null || protocols.contains(position.getProtocol())) {
            // &begin[Server_Time]
            if (useServerTime) {
                position.setDeviceTime(position.getServerTime());
                position.setFixTime(position.getServerTime());
                // &end[Server_Time]
            } else {
                position.setFixTime(position.getDeviceTime());
            }
        }
        callback.processed(false);
    }

}
