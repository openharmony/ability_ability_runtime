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

#ifndef OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_EXTENSION_CONTEXT_H

#include <memory>

#include "ability_connect_callback.h"
#include "event_handler.h"
#include "ets_free_install_observer.h"
#include "ets_runtime.h"
#include "ui_service_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
ani_object CreateEtsUIServiceExtensionContext(ani_env *env, std::shared_ptr<UIServiceExtensionContext> context);

class EtsUIServiceExtensionConnection : public AbilityConnectCallback {
public:
    explicit EtsUIServiceExtensionConnection(ani_vm *etsVm);
    virtual ~EtsUIServiceExtensionConnection();
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    void HandleOnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode);
    void HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode);
    void SetEtsConnectionObject(ani_object connObject);
    void RemoveConnectionObject();
    void CallEtsFailed(int32_t errorCode);
    void SetConnectionId(int64_t id);
    int64_t GetConnectionId();
private:
    void ReleaseObjectReference(ani_ref etsObjRef);
    ani_vm *etsVm_ = nullptr;
    ani_ref etsConnectionObject_ = nullptr;
    int64_t connectionId_ = -1;
};

class EtsUIServiceExtensionContext final {
public:
    explicit EtsUIServiceExtensionContext(
        const std::shared_ptr<UIServiceExtensionContext> &context) : context_(context) {}
    ~EtsUIServiceExtensionContext() = default;
    static EtsUIServiceExtensionContext* GetEtsUIServiceExtensionContext(ani_env *env, ani_object obj);
    static void StartAbility(ani_env *env, ani_object obj,
        ani_object callback, ani_object aniWant, ani_object aniStartOption);
    static void StartAbilityCheck(ani_env *env, ani_object obj, ani_object aniWant, ani_object aniStartOption);
    static void TerminateSelf(ani_env *env, ani_object obj, ani_object callback);
    static void StartAbilityByType(ani_env *env, ani_object obj, ani_string aniType, ani_object aniWantParam,
        ani_object abilityStartCallback, ani_object callback);
    static void StartAbilityByTypeCheck(ani_env *env, ani_object obj, ani_string aniType, ani_object aniWantParam);
    static ani_long ConnectServiceExtensionAbility(ani_env *env, ani_object obj,
        ani_object aniWant, ani_object aniOptions);
    static void DisConnectServiceExtensionAbility(ani_env *env, ani_object obj,
        ani_long aniConnectionId, ani_object callback);
    static bool BindNativeMethods(ani_env *env);
    static bool BindNativePtrCleaner(ani_env *env);
    static void Clean(ani_env *env, ani_object object);
private:
    void OnStartAbility(ani_env *env, ani_object callback, ani_object aniWant, ani_object aniStartOption);
    void OnTerminateSelf(ani_env *env, ani_object callback);
    void OnStartAbilityByType(ani_env *env, ani_string aniType, ani_object aniWantParam,
        ani_object abilityStartCallback, ani_object callback);
    ani_long OnConnectServiceExtensionAbility(ani_env *env, ani_object aniWant, ani_object aniOptions);
    void OnDisConnectServiceExtensionAbility(ani_env *env, ani_long aniConnectionId, ani_object callback);
    std::shared_ptr<UIServiceExtensionContext> GetContext();
    void InitDisplayId(AAFwk::Want &want, AAFwk::StartOptions &startOptions);
    bool CheckConnectionParam(ani_env *env, ani_object object,
        sptr<EtsUIServiceExtensionConnection>& connection, AAFwk::Want& want, int32_t accountId = -1);
    void RemoveConnection(int64_t connectId);
    void FindConnection(AAFwk::Want &want, sptr<EtsUIServiceExtensionConnection> &connection, int64_t &connectId,
        int32_t &accountId);
    std::weak_ptr<UIServiceExtensionContext> context_;
}; // EtsUIServiceExtensionContext

}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_EXTENSION_CONTEXT_H