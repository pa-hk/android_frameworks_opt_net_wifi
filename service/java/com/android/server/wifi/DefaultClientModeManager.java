/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.wifi;

import android.annotation.NonNull;
import android.net.wifi.WifiDppConfig;
import android.net.wifi.WifiManager;
import android.os.WorkSource;

/**
 * This is used for creating a public {@link ClientModeManager} instance when wifi is off.
 */
public class DefaultClientModeManager extends ScanOnlyModeImpl implements ClientModeManager {
    @Override
    public void start(@NonNull WorkSource requestorWs) {
        throw new IllegalStateException();
    }

    @Override
    public void stop() {
        throw new IllegalStateException();
    }

    @Override
    public Role getRole() {
        return null;
    }

    @Override
    public String getInterfaceName() {
        return null;
    }

    @Override
    public int syncGetWifiState() {
        return WifiManager.WIFI_STATE_DISABLED;
    }

    @Override
    public void setTrafficPoller(WifiTrafficPoller trafficPoller) {}
    @Override
    public String getCapabilities(String capaType) {
        return null;
    }
    @Override
    public int syncDppAddBootstrapQrCode(String uri) {
        return -1;
    }
    @Override
    public int syncDppBootstrapGenerate(WifiDppConfig config) {
        return -1;
    }
    @Override
    public String syncDppGetUri(int bootstrap_id) {
        return null;
    }
    @Override
    public int syncDppBootstrapRemove(int bootstrap_id) {
        return -1;
    }
    @Override
    public int syncDppListen(String frequency, int dpp_role, boolean qr_mutual, boolean netrole_ap) {
        return -1;
    }
    @Override
    public void dppStopListen() {}
    @Override
    public int syncDppConfiguratorAdd(String curve, String key, int expiry) {
        return -1;
    }
    @Override
    public int syncDppConfiguratorRemove(int config_id) {
        return -1;
    }
    @Override
    public int syncDppStartAuth(WifiDppConfig config) {
        return -1;
    }
    @Override
    public String syncDppConfiguratorGetKey(int id) {
        return null;
    }
    @Override
    public String doDriverCmd(String command) {
        return null;
    }
}
