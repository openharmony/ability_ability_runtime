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

#ifndef ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_PROXY_ADAPTER_H
#define ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_PROXY_ADAPTER_H

#include "iforeground_app_connection.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class ForegroundAppConnectionProxyAdapter
 * ForegroundAppConnectionProxyAdapter is used to send request to ability manager service.
 */
class ForegroundAppConnectionProxyAdapter : public std::enable_shared_from_this<ForegroundAppConnectionProxyAdapter> {
public:
    explicit ForegroundAppConnectionProxyAdapter(sptr<IRemoteObject> remoteObj) : remoteObj_(remoteObj) {}
    virtual ~ForegroundAppConnectionProxyAdapter() = default;

    ForegroundAppConnectionProxyAdapter(const ForegroundAppConnectionProxyAdapter&) = default;
    ForegroundAppConnectionProxyAdapter(ForegroundAppConnectionProxyAdapter&&) = default;
    ForegroundAppConnectionProxyAdapter& operator=(const ForegroundAppConnectionProxyAdapter&) = default;
    ForegroundAppConnectionProxyAdapter& operator=(ForegroundAppConnectionProxyAdapter&&) = default;

    int32_t RegisterObserver(sptr<IForegroundAppConnection> observer);

    int32_t UnregisterObserver(sptr<IForegroundAppConnection> observer);

    sptr<IRemoteObject> GetProxyObject() const;

private:
    sptr<IRemoteObject> remoteObj_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // ABILITY_RUNTIME_FOREGROUND_APP_CONNECTION_PROXY_ADAPTER_H
