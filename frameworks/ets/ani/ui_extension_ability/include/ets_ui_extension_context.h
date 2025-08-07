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
#ifndef OHOS_ABILITY_RUNTIME_ETS_UI_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_ETS_UI_EXTENSION_CONTEXT_H

#include <array>
#include <iostream>
#include <unistd.h>

#include "ani.h"
#include "ets_free_install_observer.h"
#include "ets_runtime.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ohos_application.h"
#include "open_link_options.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
ani_object CreateEtsUIExtensionContext(ani_env *env, std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> context);

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
    ani_env *AttachCurrentThread();
    void DetachCurrentThread();

protected:
    ani_vm *etsVm_ = nullptr;
    int32_t connectionId_ = -1;
    ani_ref stsConnectionRef_ = nullptr;
    bool isAttachThread_ = false;
};

class EtsUIExtensionContext final {
public:
    explicit EtsUIExtensionContext(const std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> &context)
        : context_(context) {}
    virtual ~EtsUIExtensionContext() = default;
    static EtsUIExtensionContext* GetEtsUIExtensionContext(ani_env *env, ani_object obj);
    static void TerminateSelfSync(ani_env *env, ani_object obj, ani_object callback);
    static void TerminateSelfWithResultSync(
        ani_env *env, ani_object obj, ani_object abilityResult, ani_object callback);
    static void StartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object call);
    static void StartAbilityWithOption(
        ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call);
    static ani_long ConnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    static void DisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_long connectId,
        ani_object callback);
    static void StartAbilityForResult(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback);
    static void StartAbilityForResultWithOptions(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object startOptionsObj, ani_object callback);
    static void StartServiceExtensionAbilityWithAccount(ani_env *env, ani_object aniObj,
        ani_object wantObj, ani_int aniAccountId, ani_object callbackObj);
    static void StartAbilityForResultAsCaller(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object callbackObj, ani_object optionsObj);
    static void StartServiceExtensionAbility(ani_env *env, ani_object aniObj,
        ani_object wantObj, ani_object callbackObj);
    static void SetHostPageOverlayForbidden(ani_env *env, ani_object aniObj, ani_boolean aniIsForbidden);
    static void SetColorMode(ani_env *env, ani_object aniObj, ani_enum_item aniColorMode);
    static void ReportDrawnCompleted(ani_env *env,  ani_object aniObj, ani_object callback);
    static void OpenLink(ani_env *env, ani_object aniObj, ani_string aniLink, ani_object myCallbackobj,
        ani_object optionsObj, ani_object callbackobj);
    static void OpenAtomicService(ani_env *env, ani_object aniObj, ani_string aniAppId,
        ani_object callbackobj, ani_object optionsObj);

    static bool BindNativePtrCleaner(ani_env *env);
    static void Clean(ani_env *env, ani_object object);

private:
    void OnTerminateSelf(ani_env *env, ani_object obj, ani_object callback);
    void OnTerminateSelfWithResult(ani_env *env, ani_object obj, ani_object abilityResult, ani_object callback);
    void OnStartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call);
    void OnStartAbilityForResult(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptinsObj,
        ani_object callback);
    void AddFreeInstallObserver(ani_env *env, const AAFwk::Want &want, ani_object callbackObj,
        std::shared_ptr<UIExtensionContext> context, bool isAbilityResult = false, bool isOpenLink = false);
    ani_long OnConnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    void OnDisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_long connectId,
        ani_object callback);
    void OnStartServiceExtensionAbilityWithAccount(ani_env *env, ani_object aniObj,
        ani_object wantObj, ani_int aniAccountId, ani_object callbackObj);
    void OnStartAbilityForResultAsCaller(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object callbackObj, ani_object optionsObj);
    void OnStartServiceExtensionAbility(ani_env *env, ani_object aniObj,
        ani_object wantObj, ani_object callbackObj);
    void OnSetHostPageOverlayForbidden(ani_env *env, ani_object aniObj, ani_boolean aniIsForbidden);
    RuntimeTask CreateRuntimeTask(ani_vm *etsVm, ani_ref callbackRef);
    void OnOpenLink(ani_env *env, ani_object aniObj, ani_string aniLink, ani_object myCallbackobj,
        ani_object optionsObj, ani_object callbackobj);
    void OnOpenAtomicService(ani_env *env, ani_object aniObj, ani_string aniAppId,
        ani_object callbackobj, ani_object optionsObj);

    static bool CheckConnectionParam(ani_env *env, ani_object connectOptionsObj,
        sptr<EtsUIExtensionConnection>& connection, AAFwk::Want& want);
    void OnSetColorMode(ani_env *env, ani_object aniCls, ani_enum_item aniColorMode);
    void OnReportDrawnCompleted(ani_env *env,  ani_object aniCls, ani_object callback);
    void OpenLinkInner(ani_env *env, ani_object aniObj, ani_string aniLink, ani_object myCallbackobj,
        ani_object optionsObj, ani_object callbackobj, bool haveOptionsParm, bool haveCallBackParm);
    void CreateOpenLinkTask(ani_env *env, const ani_object callbackobj,
        std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> context, AAFwk::Want &want, int &requestCode);
    void OpenAtomicServiceInner(ani_env *env, ani_object aniObj, AAFwk::Want &want, AAFwk::StartOptions &options,
        std::string appId, ani_object callbackobj);
    void UnwrapCompletionHandlerInStartOptions(ani_env *env, ani_object param, AAFwk::StartOptions &options);
    void CreateOnRequestResultCallback(ani_env *env, ani_ref refCompletionHandler,
        OnRequestResult &onRequestCallback, const char *callbackName);

#ifdef SUPPORT_SCREEN
    void InitDisplayId(AAFwk::Want &want);
    void InitDisplayId(AAFwk::Want &want, AAFwk::StartOptions &startOptions, ani_env *env, ani_object optionsObj);
#endif

protected:
    std::weak_ptr<OHOS::AbilityRuntime::UIExtensionContext> context_;
    sptr<EtsFreeInstallObserver> freeInstallObserver_ = nullptr;
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
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_UI_EXTENSION_CONTEXT_H