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

import android.net.wifi.WifiDppConfig;

/**
 * Base class for ClientModeManager.
 */
public interface ClientModeManager extends ActiveModeManager, ClientMode {
    int syncGetWifiState();

    @Override
    ClientRole getRole();

    // QC value-adds
    void setTrafficPoller(WifiTrafficPoller trafficPoller);
    String getCapabilities(String capaType);
    int syncDppAddBootstrapQrCode(String uri);
    int syncDppBootstrapGenerate(WifiDppConfig config);
    String syncDppGetUri(int bootstrap_id);
    int syncDppBootstrapRemove(int bootstrap_id);
    int syncDppListen(String frequency, int dpp_role, boolean qr_mutual, boolean netrole_ap);
    void dppStopListen();
    int syncDppConfiguratorAdd(String curve, String key, int expiry);
    int syncDppConfiguratorRemove(int config_id);
    int syncDppStartAuth(WifiDppConfig config);
    String syncDppConfiguratorGetKey(int id);
    String doDriverCmd(String command);
    // end QC value-adds
}
