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

#ifndef OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_PROXY_H
#define OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_PROXY_H

#include <memory>

#include "ani.h"
#include "ets_runtime.h"
#include "ui_service_proxy.h"

namespace OHOS {
namespace AAFwk {
using namespace AbilityRuntime;

class EtsUIServiceProxy {
public:
    static ani_object CreateEtsUIServiceProxy(ani_env *env, const sptr<IRemoteObject> &impl,
                                              int64_t connectionId, const sptr<IRemoteObject> &hostProxy);
    static ani_object CreateEmptyProxyObject(ani_env *env);
    EtsUIServiceProxy(const sptr<IRemoteObject> &impl, const sptr<IRemoteObject> &hostProxy);
    virtual ~EtsUIServiceProxy();
    static EtsUIServiceProxy* GetEtsUIServiceProxy(ani_env *env, ani_object obj);
    static void SendData(ani_env *env, ani_object obj, ani_object data);
    void SetConnectionId(int64_t id) { connectionId_ = id; }
    int64_t GetConnectionId() { return connectionId_; }
private:
    void OnSendData(ani_env *env, ani_object data);

protected:
    sptr<OHOS::AAFwk::IUIService> proxy_ = nullptr;
    int64_t connectionId_ = 0;
    sptr<IRemoteObject> hostProxy_ = nullptr;
};

} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_PROXY_H