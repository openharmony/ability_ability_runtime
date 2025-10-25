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

#ifndef ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_CLIENT_H
#define ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_CLIENT_H

#include "foreground_app_connection.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class ForegroundAppConnectionClient
 * ForegroundAppConnectionClient is used to manage connection observer.
 */
class ForegroundAppConnectionClientImpl;
class ForegroundAppConnectionClient {
public:
    static ForegroundAppConnectionClient& GetInstance();
    ForegroundAppConnectionClient(const ForegroundAppConnectionClient&) = delete;

    /**
     * @brief Destructor.
     *
     */
    virtual ~ForegroundAppConnectionClient() = default;

    /**
     * register connection state observer.
     *
     * @param observer the observer callback.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RegisterObserver(const std::shared_ptr<ForegroundAppConnection> &observer);

    /**
     * unregister connection state observer.
     *
     * @param observer the observer callback.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t UnregisterObserver(const std::shared_ptr<ForegroundAppConnection> &observer);

private:
    ForegroundAppConnectionClient();
    ForegroundAppConnectionClient& operator=(const ForegroundAppConnectionClient&) = delete;
    ForegroundAppConnectionClient& operator=(ForegroundAppConnectionClient&&) = delete;

    std::shared_ptr<ForegroundAppConnectionClientImpl> clientImpl_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_CLIENT_H
