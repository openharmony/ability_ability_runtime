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

#ifndef ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_H
#define ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_H

#include "foreground_app_connection_data.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class ForegroundAppConnection
 * ForegroundAppConnection is used to notify connection relationship of foreground app component.
 */
class ForegroundAppConnection {
public:
    /**
     * @brief Constructor.
     *
     */
    ForegroundAppConnection() = default;

    /**
     * @brief Destructor.
     *
     */
    virtual ~ForegroundAppConnection() = default;

    /**
     * called when foreground app is connected.
     *
     * @param data connection relationship data.
     */
    virtual void OnForegroundAppConnected(const ForegroundAppConnectionData &data) = 0;

    /**
     * called when foreground app is disconnected.
     *
     * @param data connection relationship data.
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

    /**
     * called when service was died.
     *
     */
    virtual void OnServiceDied() {}
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_H
