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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_ETS_ABILITY_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_ETS_ABILITY_CONTEXT_H

#include "ability_context.h"
#include "ability_manager_client.h"
#include "ani.h"
#include "configuration.h"
#include "ets_free_install_observer.h"
#include "ets_native_reference.h"
#include "ets_runtime.h"
#include "ohos_application.h"
#include "open_link_options.h"

namespace OHOS {
namespace AbilityRuntime {
using OHOSApplication = AppExecFwk::OHOSApplication;

class ETSAbilityConnection : public AbilityConnectCallback {
public:
    explicit ETSAbilityConnection(ani_vm *etsVm);
    ~ETSAbilityConnection();
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;
    void CallEtsFailed(int32_t errorCode);
    void SetConnectionId(int32_t id);
    int32_t GetConnectionId() { return connectionId_; }
    void SetConnectionRef(ani_object connectOptionsObj);
    void RemoveConnectionObject();
protected:
    ani_vm *etsVm_ = nullptr;
    int32_t connectionId_ = -1;
    ani_ref stsConnectionRef_ = nullptr;
};

class EtsAbilityContext final {
public:
    explicit EtsAbilityContext(std::shared_ptr<AbilityContext> context) : context_(std::move(context)) {}
    ~EtsAbilityContext() = default;

    static void StartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object call);
    static void StartAbilityWithOptions(
        ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call);
    static void StartAbilityForResult(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback);
    static void StartAbilityForResultWithOptions(
        ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj, ani_object callback);
    static void TerminateSelf(ani_env *env, ani_object aniObj, ani_object callback);
    static void TerminateSelfWithResult(ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback);
    static void ReportDrawnCompleted(ani_env *env, ani_object aniObj, ani_object call);
    static void StartServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object callbackobj);
    static void OpenLink(ani_env *env, ani_object aniObj, ani_string aniLink,
        ani_object myCallbackobj, ani_object optionsObj, ani_object callbackobj);
    static bool IsTerminating(ani_env *env, ani_object aniObj);
    static void MoveAbilityToBackground(ani_env *env, ani_object aniObj, ani_object callbackobj);
    static void RequestModalUIExtension(ani_env *env, ani_object aniObj, ani_object pickerWantObj,
        ani_object callbackobj);
    static void BackToCallerAbilityWithResult(ani_env *env, ani_object aniObj,
        ani_object abilityResultObj, ani_string requestCodeObj, ani_object callBackObj);
    static void SetMissionLabel(ani_env *env, ani_object aniObj, ani_string labelObj,
        ani_object callbackObj);
    static ani_int ConnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    static void DisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_double connectId,
        ani_object callback);
    static void SetColorMode(ani_env *env, ani_object aniObj, ani_enum_item colorMode);
    static ani_object StartAbilityByType(
        ani_env *env, ani_object aniObj, ani_string aniType, ani_ref aniWantParam, ani_object startCallback);
    static void ConfigurationUpdated(ani_env *env, std::shared_ptr<AppExecFwk::ETSNativeReference> &etsContext,
        const std::shared_ptr<AppExecFwk::Configuration> &config);

    static void Clean(ani_env *env, ani_object object);
    static ani_object SetEtsAbilityContext(ani_env *env, std::shared_ptr<AbilityContext> context);
    static EtsAbilityContext *GetEtsAbilityContext(ani_env *env, ani_object aniObj);
    static bool IsInstanceOf(ani_env *env, ani_object aniObj);

private:
    void InheritWindowMode(ani_env *env, ani_object aniObj, AAFwk::Want &want);
    void OnStartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call);
    void OnStartAbilityForResult(
        ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj, ani_object callback);
    void OnTerminateSelf(ani_env *env, ani_object aniObj, ani_object callback);
    void OnTerminateSelfWithResult(ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback);
    void OnReportDrawnCompleted(ani_env *env, ani_object aniObj, ani_object call);
    void AddFreeInstallObserver(ani_env *env, const AAFwk::Want &want, ani_object callback,
        const std::shared_ptr<AbilityContext> &context, bool isAbilityResult = false, bool isOpenLink = false);
    void StartAbilityForResultInner(ani_env *env, const AAFwk::StartOptions &startOptions, AAFwk::Want &want,
        std::shared_ptr<AbilityContext> context, ani_object startOptionsObj, ani_object callback);
    void OnStartServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object callbackobj);
    void OnOpenLink(ani_env *env, ani_object aniObj, ani_string aniLink, ani_object myCallbackobj,
        ani_object optionsObj, ani_object callbackobj, bool haveOptionsParm, bool haveCallBackParm);
    bool OnIsTerminating(ani_env *env, ani_object aniObj);
    void OnMoveAbilityToBackground(ani_env *env, ani_object aniObj, ani_object callback);
    void OnRequestModalUIExtension(ani_env *env, ani_object aniObj, ani_object pickerWantObj,
        ani_object callbackObj);
    void OnBackToCallerAbilityWithResult(ani_env *env, ani_object aniObj,
        ani_object abilityResultObj, ani_string requestCodeObj, ani_object callBackObj);
    void OnSetMissionLabel(ani_env *env, ani_object aniObj, ani_string labelObj, ani_object callbackObj);
    ani_int OnConnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    void OnDisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_double connectId,
        ani_object callback);
    void OnSetColorMode(ani_env *env, ani_object aniObj, ani_enum_item colorMode);
    ani_object OnStartAbilityByType(
        ani_env *env, ani_object aniObj, ani_string aniType, ani_ref aniWantParam, ani_object startCallback);

    void UnWrapOpenLinkOptions(ani_env *env, ani_object optionsObj, AAFwk::OpenLinkOptions &openLinkOptions,
        AAFwk::Want &want);
    void CreateOpenLinkTask(ani_env *env, const ani_object callbackobj,
        std::shared_ptr<AbilityContext> context, AAFwk::Want &want, int &requestCode);
    int32_t GenerateRequestCode();

    std::weak_ptr<AbilityContext> context_;
    static std::mutex requestCodeMutex_;
    sptr<EtsFreeInstallObserver> freeInstallObserver_ = nullptr;
};

struct EtsConnectionKey {
    AAFwk::Want want;
    int32_t id = 0;
    int32_t accountId = 0;
};

struct EtsKeyCompare {
    bool operator()(const EtsConnectionKey &key1, const EtsConnectionKey &key2) const
    {
        return key1.id < key2.id;
    }
};

ani_object CreateEtsAbilityContext(ani_env *env, std::shared_ptr<AbilityContext> context);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_ETS_ABILITY_CONTEXT_H
