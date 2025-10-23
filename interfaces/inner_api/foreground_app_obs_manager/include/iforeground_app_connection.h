/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITYRUNTIME_IFOREGROUND_APP_CONNECTION_H
#define OHOS_ABILITYRUNTIME_IFOREGROUND_APP_CONNECTION_H

#include "foreground_app_connection_data.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class IForegroundAppConnection
 * IForegroundAppConnection is used to notify connection relationship of foreground app component.
 */
class IForegroundAppConnection : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.abilityruntime.foregroundappconnection");

    /**
     * called when foreground app was connected.
     *
     * @param data foreground app relationship data.
     */
    virtual void OnForegroundAppConnected(const ForegroundAppConnectionData &data) = 0;

    /**
     * called when foreground app was disconnected.
     *
     * @param data foreground app relationship data.
     */
    virtual void OnForegroundAppDisconnected(const ForegroundAppConnectionData &data) = 0;

    /**
     * called when startAbilityForResult begin.
     *
     * @param callerPid the pid of startAbilityForResult's caller.
     * @param callerUid the uid of startAbilityForResult's caller.
     * @param bundleName the bundleName of startAbilityForResult's caller.
     */
    virtual void OnForegroundAppCallerStarted(int32_t callerPid, int32_t callerUid,
        const std::string &bundleName) = 0;

    enum ForegroundAppConnectionCmd {
        // ipc id for OnForegroundAppConnected
        ON_FOREGROUND_APP_CONNECTED = 0,

        // ipc id for OnForegroundAppDisconnected
        ON_FOREGROUND_APP_DISCONNECTED,

        // ipc id for OnForegroundAppCallerStarted
        ON_FOREGROUND_APP_CALLER_STARTED,

        // maximum of enum
        CMD_MAX
    };
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITYRUNTIME_IFOREGROUND_APP_CONNECTION_H
