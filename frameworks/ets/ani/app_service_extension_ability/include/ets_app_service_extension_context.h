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
#ifndef OHOS_ABILITY_RUNTIME_ETS_APP_SERVICE_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_ETS_APP_SERVICE_EXTENSION_CONTEXT_H

#include <memory>

#include "ets_service_extension_context.h"
#include "ability_connect_callback.h"
#include "app_service_extension_context.h"
#include "ets_free_install_observer.h"
#include "event_handler.h"

namespace OHOS {
namespace AbilityRuntime {

class EtsAppServiceExtensionContext final {
public:
    explicit EtsAppServiceExtensionContext(const std::shared_ptr<AppServiceExtensionContext> &context)
        : context_(context) {}
    ~EtsAppServiceExtensionContext() = default;

    static void Finalizer(ani_env *env, void *data, void *hint);
    static void TerminateSelf(ani_env *env, ani_object obj, ani_object callback);
    static ani_long ConnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    static void DisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_long connectId,
        ani_object callback);
    static void StartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object call);
    static void StartAbilityWithOption(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj,
        ani_object call);
    static EtsAppServiceExtensionContext *GetEtsAbilityContext(ani_env *env, ani_object obj);
    std::weak_ptr<AppServiceExtensionContext> GetAbilityContext()
    {
        return context_;
    }

private:
    std::weak_ptr<AppServiceExtensionContext> context_;
    sptr<EtsFreeInstallObserver> freeInstallObserver_ = nullptr;
    void OnTerminateSelf(ani_env *env, ani_object obj, ani_object callback);
    ani_long OnConnectAppServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    void OnDisconnectAppServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_long connectId,
        ani_object callback);
    void OnStartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj,
        ani_object callbackObj);
};

ani_object CreateEtsAppServiceExtensionContext(ani_env *env, std::shared_ptr<AppServiceExtensionContext> context);

class ETSAppServiceExtensionConnection : public ETSServiceExtensionConnection {
public:
    explicit ETSAppServiceExtensionConnection(ani_vm *env) : ETSServiceExtensionConnection(env) {}
    virtual ~ETSAppServiceExtensionConnection() {}
    void RemoveConnection();
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_SERVICE_EXTENSION_CONTEXT_H