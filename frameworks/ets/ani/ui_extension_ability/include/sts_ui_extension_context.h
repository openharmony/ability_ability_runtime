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
#ifndef OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTEXT_H

#include "sts_runtime.h"
#include <array>
#include <iostream>
#include <unistd.h>
#include "ui_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ohos_application.h"
#include "sts_free_install_observer.h"

namespace OHOS {
namespace AbilityRuntime {
[[maybe_unused]] static void TerminateSelfSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
    [[maybe_unused]] ani_object callback);
[[maybe_unused]] static void TerminateSelfWithResultSync([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object obj, [[maybe_unused]] ani_object abilityResult, [[maybe_unused]] ani_object callback);
ani_object CreateStsUIExtensionContext(ani_env *env, std::shared_ptr<UIExtensionContext> context);

bool BindNativeMethods(ani_env *env, ani_class &cls);

class EtsUIExtensionConnection : public AbilityConnectCallback {
public:
    explicit EtsUIExtensionConnection(ani_vm *etsVm);
    ~EtsUIExtensionConnection();
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    void CallEtsFailed(int32_t errorCode);
    void SetConnectionId(int32_t id);
    int32_t GetConnectionId() { return connectionId_; }
    void SetConnectionRef(ani_object connectOptionsObj);

protected:
    ani_vm *etsVm_ = nullptr;
    int32_t connectionId_ = -1;
    ani_ref stsConnectionRef_ = nullptr;
};

class StsUIExtensionContext final {
public:
    static StsUIExtensionContext &GetInstance()
    {
        static StsUIExtensionContext instance;
        return instance;
    }
    void StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
        ani_object wantObj, ani_object opt, ani_object call);
    static UIExtensionContext* GetAbilityContext(ani_env *env, ani_object obj);
    void AddFreeInstallObserver(ani_env *env, const AAFwk::Want &want,
        ani_object callback, UIExtensionContext* context);
    static void NativeSetColorMode(ani_env *env, ani_object aniCls, ani_enum_item aniColorMode);
    static void NativeReportDrawnCompleted(ani_env *env,  ani_object aniCls, ani_object callback);
    static ani_double OnConnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    static void OnDisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_int connectId,
        ani_object connectOptionsObj);

private:
    static bool CheckConnectionParam(ani_env *env, ani_object connectOptionsObj,
        sptr<EtsUIExtensionConnection>& connection, AAFwk::Want& want);

    sptr<StsFreeInstallObserver> freeInstallObserver_ = nullptr;
};

struct EtsUIExtensionConnectionKey {
    AAFwk::Want want;
    int32_t id;
};

struct Etskey_compare {
    bool operator()(const EtsUIExtensionConnectionKey &key1, const EtsUIExtensionConnectionKey &key2) const
    {
        if (key1.id < key2.id) {
            return true;
        }
        return false;
    }
};

}  // namespace AbilityRuntime
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTEXT_H