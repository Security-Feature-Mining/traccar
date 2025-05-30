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
package org.traccar.helper;

import io.netty.channel.Channel;
import io.netty.channel.socket.DatagramChannel;

public final class NetworkUtil {

    private NetworkUtil() {
    }

    // &begin[Network_Session]
    public static String session(Channel channel) {
        char transport = channel instanceof DatagramChannel ? 'U' : 'T';
        return transport + channel.id().asShortText();
    }
    // &end[Network_Session]

}
