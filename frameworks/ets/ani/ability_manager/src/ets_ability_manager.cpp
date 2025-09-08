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

#include "ets_ability_manager.h"

#include "ability_business_error.h"
#include "ability_context.h"
#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "ability_manager_interface.h"
#include "acquire_share_data_callback_stub.h"
#include "ani_base_context.h"
#include "ani_common_ability_state_data.h"
#include "ani_common_configuration.h"
#include "ani_common_want.h"
#include "ani_enum_convert.h"
#include "app_mgr_interface.h"
#include "ets_ability_foreground_state_observer.h"
#include "ets_ability_manager_utils.h"
#include "ets_error_utils.h"
#include "ets_query_erms_observer.h"
#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* ETS_ABILITY_MANAGER_NAMESPACE = "L@ohos/app/ability/abilityManager/abilityManager;";
constexpr const char* ETS_ABILITY_MANAGER_SIGNATURE_ARRAY = ":Lescompat/Array;";
constexpr const char* ETS_ABILITY_MANAGER_SIGNATURE_CALLBACK = "Lutils/AbilityUtils/AsyncCallbackWrapper;:V";
constexpr const char *ON_OFF_TYPE_ABILITY_FOREGROUND_STATE = "abilityForegroundState";
constexpr int32_t ERR_FAILURE = -1;

sptr<AAFwk::AcquireShareDataCallbackStub> CreateShareDataCallbackStub(
    ani_env *env, ani_ref callbackRef)
{
    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GetVM failed");
        return nullptr;
    }
    auto shareDataCallbackStub = new (std::nothrow) AAFwk::AcquireShareDataCallbackStub();
    if (shareDataCallbackStub == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null shareDataCallbackStub");
        return nullptr;
    }
    auto handler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    shareDataCallbackStub->SetHandler(handler);
    AAFwk::ShareRuntimeTask task =
        [aniVM, callbackRef](int32_t resultCode, const AAFwk::WantParams &wantParam) {
            ani_env *env = nullptr;
            ani_status status = aniVM->GetEnv(ANI_VERSION_1, &env);
            if (status != ANI_OK || env == nullptr) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
                return;
            }
            if (resultCode != 0) {
                AppExecFwk::AsyncCallback(env, static_cast<ani_object>(callbackRef),
                    EtsErrorUtil::CreateErrorByNativeErr(env, resultCode), nullptr);
                env->GlobalReference_Delete(callbackRef);
                return;
            }
            ani_ref wantParamRef = AppExecFwk::WrapWantParams(env, wantParam);
            if (wantParamRef == nullptr) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "null wantParamRef");
                AppExecFwk::AsyncCallback(env, static_cast<ani_object>(callbackRef),
                    EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_CODE_INNER), nullptr);
                env->GlobalReference_Delete(callbackRef);
                return;
            }
            AppExecFwk::AsyncCallback(env, static_cast<ani_object>(callbackRef),
                EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), static_cast<ani_object>(wantParamRef));
            env->GlobalReference_Delete(callbackRef);
        };
    shareDataCallbackStub->SetShareRuntimeTask(task);
    return shareDataCallbackStub;
}
}

class EtsAbilityManager final {
public:
    static ani_object GetForegroundUIAbilities(ani_env *env);
    static void GetForegroundUIAbilitiesCallBack(ani_env *env, ani_object callbackObj);
    static void GetTopAbility(ani_env *env, ani_object callback);
    static void GetAbilityRunningInfos(ani_env *env, ani_object callback);
    static void IsEmbeddedOpenAllowed(ani_env *env, ani_object contextObj, ani_string aniAppId, ani_object callbackObj);
    static void NativeOn(ani_env *env, ani_string aniType, ani_object aniObserver);
    static void NativeOff(ani_env *env, ani_string aniType, ani_object aniObserver);
    static void NativeNotifyDebugAssertResult(ani_env *env, ani_string aniSessionId, ani_object userStatusObj,
        ani_object callbackObj);
    static void NativeNotifyDebugAssertResultCheck(ani_env *env, ani_string aniSessionId, ani_object userStatusObj);
    static void NativeSetResidentProcessEnabled(ani_env *env, ani_string aniBundleName, ani_boolean enabled,
        ani_object callbackObj);
    static void NativeSetResidentProcessEnabledCheck(ani_env *env, ani_string aniBundleName);
    static void NativeAcquireShareData(ani_env *env, ani_int aniMissionId, ani_object callbackObj);
    static void NativeUpdateConfiguration(ani_env *env, ani_object configObj, ani_object callbackObj);
    static void QueryAtomicServiceStartupRule(ani_env *env, ani_object contextObj,
        ani_string aniAppId, ani_object callbackObj);
    static void QueryAtomicServiceStartupRuleCheck(ani_env *env, ani_object contextObj);
    static void GetExtensionRunningInfos(ani_env *env, ani_int upperLimit, ani_object callback);
private:
    static sptr<AppExecFwk::IAbilityManager> GetAbilityManagerInstance();
    static sptr<AppExecFwk::IAppMgr> GetAppManagerInstance();
    static int AddQueryERMSObserver(ani_vm *vm, sptr<IRemoteObject> token, const std::string &appId,
        const std::string &startTime, ani_object callbackObj);
    static void QueryAtomicServiceStartupRuleInner(std::string appId, std::string startTime,
        sptr<IRemoteObject> token);
    static sptr<AbilityRuntime::ETSAbilityForegroundStateObserver> observerForeground_;
    static sptr<AbilityRuntime::EtsQueryERMSObserver> queryERMSObserver_;
};

sptr<AbilityRuntime::ETSAbilityForegroundStateObserver> EtsAbilityManager::observerForeground_ = nullptr;
sptr<AbilityRuntime::EtsQueryERMSObserver> EtsAbilityManager::queryERMSObserver_ = nullptr;

sptr<AppExecFwk::IAbilityManager> EtsAbilityManager::GetAbilityManagerInstance()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> abilityManagerObj = systemAbilityManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    return iface_cast<AppExecFwk::IAbilityManager>(abilityManagerObj);
}

sptr<AppExecFwk::IAppMgr> EtsAbilityManager::GetAppManagerInstance()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> appObject = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    return iface_cast<AppExecFwk::IAppMgr>(appObject);
}

ani_object EtsAbilityManager::GetForegroundUIAbilities(ani_env *env)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call GetForegroundUIAbilities");

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return nullptr;
    }

    sptr<AppExecFwk::IAbilityManager> abilityManager = GetAbilityManagerInstance();
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "abilityManager is null");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    std::vector<AppExecFwk::AbilityStateData> list;
    int32_t ret = abilityManager->GetForegroundUIAbilities(list);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed: ret=%{public}d", ret);
        AbilityRuntime::AbilityErrorCode code = AbilityRuntime::GetJsErrorCodeByNativeError(ret);
        AbilityRuntime::EtsErrorUtil::ThrowError(env, code);
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "GetForegroundUIAbilities succeeds, list.size=%{public}zu", list.size());
    ani_object aniArray = AppExecFwk::CreateAniAbilityStateDataArray(env, list);
    if (aniArray == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null aniArray");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    return aniArray;
}

void EtsAbilityManager::GetForegroundUIAbilitiesCallBack(ani_env *env, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call GetForegroundUIAbilitiesCallBack");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }

    sptr<AppExecFwk::IAbilityManager> abilityManager = GetAbilityManagerInstance();
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "abilityManager is null");
        AppExecFwk::AsyncCallback(env, callbackObj,
            EtsErrorUtil::CreateError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER), nullptr);
        return;
    }
    std::vector<AppExecFwk::AbilityStateData> list;
    int32_t ret = abilityManager->GetForegroundUIAbilities(list);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed: ret=%{public}d", ret);
        AbilityRuntime::AbilityErrorCode code = AbilityRuntime::GetJsErrorCodeByNativeError(ret);
        AppExecFwk::AsyncCallback(env, callbackObj, EtsErrorUtil::CreateError(env, code), nullptr);
        return;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "GetForegroundUIAbilities succeeds, list.size=%{public}zu", list.size());
    ani_object aniArray = AppExecFwk::CreateAniAbilityStateDataArray(env, list);
    if (aniArray == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null aniArray");
        AppExecFwk::AsyncCallback(env, callbackObj,
            EtsErrorUtil::CreateError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER), nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, callbackObj, EtsErrorUtil::CreateErrorByNativeErr(env, ERR_OK), aniArray);
}

void EtsAbilityManager::GetTopAbility(ani_env *env, ani_object callback)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call GetTopAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not system app");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return;
    }
    AppExecFwk::ElementName elementName = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility();
    int resultCode = 0;
    ani_object elementNameobj = AppExecFwk::WrapElementName(env, elementName);
    if (elementNameobj == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null elementNameobj");
        resultCode = ERR_FAILURE;
    }
    AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        elementNameobj);
    return;
}

void EtsAbilityManager::GetAbilityRunningInfos(ani_env *env, ani_object callback)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "GetAbilityRunningInfos");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }
    std::vector<AAFwk::AbilityRunningInfo> infos;
    auto errcode = AAFwk::AbilityManagerClient::GetInstance()->GetAbilityRunningInfos(infos);
    ani_object retObject = nullptr;
    AbilityManagerEts::WrapAbilityRunningInfoArray(env, retObject, infos);
    AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env, errcode), retObject);
}

void EtsAbilityManager::IsEmbeddedOpenAllowed(ani_env *env, ani_object contextObj,
    ani_string aniAppId, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "IsEmbeddedOpenAllowed");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null context");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param context failed, must not be nullptr.");
        return;
    }
    auto uiAbilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (uiAbilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null UIAbilityContext");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param context failed, must be UIAbilityContext.");
        return;
    }
    std::string appId;
    if (!AppExecFwk::GetStdString(env, aniAppId, appId)) {
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param appId failed, must be a string.");
        return;
    }
    auto token = uiAbilityContext->GetToken();
    ani_boolean ret = AAFwk::AbilityManagerClient::GetInstance()->IsEmbeddedOpenAllowed(token, appId);
    AppExecFwk::AsyncCallback(env, callbackObj,
        EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK),  AppExecFwk::CreateBoolean(env, ret));
}

int EtsAbilityManager::AddQueryERMSObserver(ani_vm *vm, sptr<IRemoteObject> token, const std::string &appId,
    const std::string &startTime, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "AddQueryERMSObserver");
    if (queryERMSObserver_ == nullptr) {
        queryERMSObserver_ = sptr<EtsQueryERMSObserver>::MakeSptr(vm);
    }
    queryERMSObserver_->AddEtsObserverObject(appId, startTime, callbackObj);
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->AddQueryERMSObserver(token, queryERMSObserver_);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "addQueryERMSObserver error");
        AtomicServiceStartupRule rule;
        queryERMSObserver_->OnQueryFinished(appId, startTime, rule, AAFwk::INNER_ERR);
        return ret;
    }
    return ERR_OK;
}

void EtsAbilityManager::QueryAtomicServiceStartupRuleCheck(ani_env *env, ani_object contextObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "QueryAtomicServiceStartupRule");
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null context");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param context failed, must not be nullptr.");
        return;
    }
    auto uiAbilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (uiAbilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null UIAbilityContext");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param context failed, must be UIAbilityContext.");
        return;
    }
}

void EtsAbilityManager::QueryAtomicServiceStartupRule(ani_env *env, ani_object contextObj,
    ani_string aniAppId, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "QueryAtomicServiceStartupRule");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, contextObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null context");
        return;
    }
    auto uiAbilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (uiAbilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null UIAbilityContext");
        return;
    }
    std::string appId;
    if (!AppExecFwk::GetStdString(env, aniAppId, appId)) {
        return;
    }
    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get aniVM failed");
        return;
    }
    auto token = uiAbilityContext->GetToken();
    std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count());
    auto ret = AddQueryERMSObserver(aniVM, token, appId, startTime, callbackObj);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "AddQueryERMSObserver failed, ret=%{public}d", ret);
        return;
    }
    QueryAtomicServiceStartupRuleInner(appId, startTime, token);
}

void EtsAbilityManager::QueryAtomicServiceStartupRuleInner(std::string appId, std::string startTime,
    sptr<IRemoteObject> token)
{
    auto rule = std::make_shared<AtomicServiceStartupRule>();
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->QueryAtomicServiceStartupRule(token,
        appId, startTime, *rule);
    if (ret== AAFwk::ERR_ECOLOGICAL_CONTROL_STATUS) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "openning dialog to confirm");
        return;
    }
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "query failed: %{public}d", ret);
        queryERMSObserver_->OnQueryFinished(appId, startTime, *rule, ret);
        return;
    }
    queryERMSObserver_->OnQueryFinished(appId, startTime, *rule, ERR_OK);
}

void EtsAbilityManager::NativeOn(ani_env *env, ani_string aniType, ani_object aniObserver)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "nativeOn called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "env null ptr");
        return;
    }
    std::string strType;
    if (!AppExecFwk::GetStdString(env, aniType, strType) || strType != ON_OFF_TYPE_ABILITY_FOREGROUND_STATE) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "GetStdString failed");
        EtsErrorUtil::ThrowInvalidParamError(env,
            "Parse param observer failed, must be a AbilityForegroundStateObserver.");
        return;
    }
    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get aniVM failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Get aniVm failed.");
        return;
    }
    if (observerForeground_ == nullptr) {
        observerForeground_ = new (std::nothrow) AbilityRuntime::ETSAbilityForegroundStateObserver(aniVM);
        if (observerForeground_ == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null observerForeground_");
            EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
            return;
        }
    }
    if (observerForeground_->IsEmpty()) {
        auto appManager = GetAppManagerInstance();
        if (appManager == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "appManager null ptr");
            EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
            return;
        }
        int32_t ret = appManager->RegisterAbilityForegroundStateObserver(observerForeground_);
        TAG_LOGD(AAFwkTag::ABILITYMGR, "ret: %{public}d", ret);
        if (ret != NO_ERROR) {
            EtsErrorUtil::ThrowErrorByNativeErr(env, static_cast<int32_t>(ret));
            return;
        }
    }
    observerForeground_->AddEtsObserverObject(env, aniObserver);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "nativeOn end");
}

void EtsAbilityManager::NativeOff(ani_env *env, ani_string aniType, ani_object aniObserver)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "nativeOff called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "env null ptr");
        return;
    }
    std::string strType;
    if (!AppExecFwk::GetStdString(env, aniType, strType)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "GetStdString failed");
        EtsErrorUtil::ThrowInvalidParamError(env,
            "Parse param observer failed, must be a AbilityForegroundStateObserver.");
        return;
    }
    if (observerForeground_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null observer");
        EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    ani_status status = ANI_OK;
    ani_boolean isUndefined = false;
    if ((status = env->Reference_IsUndefined(aniObserver, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Failed to check undefined status : %{public}d", status);
        return;
    }
    if (!isUndefined) {
        observerForeground_->RemoveEtsObserverObject(aniObserver);
    } else {
        observerForeground_->RemoveAllEtsObserverObject();
    }
    if (observerForeground_->IsEmpty()) {
        auto appManager = GetAppManagerInstance();
        if (appManager == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "appManager null ptr");
            EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
            return;
        }
        int32_t ret = appManager->UnregisterAbilityForegroundStateObserver(observerForeground_);
        TAG_LOGD(AAFwkTag::ABILITYMGR, "ret: %{public}d", ret);
        if (ret != NO_ERROR) {
            EtsErrorUtil::ThrowErrorByNativeErr(env, static_cast<int32_t>(ret));
        }
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "nativeOff end");
}

void EtsAbilityManager::NativeNotifyDebugAssertResultCheck(ani_env *env, ani_string aniSessionId,
    ani_object userStatusObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "NativeNotifyDebugAssertResultCheck called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "env null ptr");
        return;
    }
    std::string sessionId;
    if (!AppExecFwk::GetStdString(env, aniSessionId, sessionId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "convert sessionId failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param sessionId failed, must be a string.");
        return;
    }

    uint64_t assertSessionId = std::stoull(sessionId);
    if (assertSessionId == 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "convert sessionId failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param sessionId failed, value must not be equal to zero.");
        return;
    }
    int32_t userStatus;
    if (!AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, userStatusObj, userStatus)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "convert status failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param status failed, must be a UserStatus.");
        return;
    }
}

void EtsAbilityManager::NativeNotifyDebugAssertResult(ani_env *env, ani_string aniSessionId,
    ani_object userStatusObj, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "NativeNotifyDebugAssertResult called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "env null ptr");
        return;
    }
    std::string sessionId;
    if (!AppExecFwk::GetStdString(env, aniSessionId, sessionId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "convert sessionId failed");
        return;
    }

    uint64_t assertSessionId = std::stoull(sessionId);
    if (assertSessionId == 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "convert sessionId failed");
        return;
    }
    int32_t userStatus;
    if (!AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, userStatusObj, userStatus)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "convert status failed");
        return;
    }
    auto amsClient = AAFwk::AbilityManagerClient::GetInstance();
    if (amsClient == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null amsClient");
        AppExecFwk::AsyncCallback(env, callbackObj,
            EtsErrorUtil::CreateErrorByNativeErr(env, AAFwk::INNER_ERR), nullptr);
        return;
    }
    auto ret = amsClient->NotifyDebugAssertResult(assertSessionId, static_cast<AAFwk::UserStatus>(userStatus));
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed %{public}d", ret);
    }
    AppExecFwk::AsyncCallback(env, callbackObj, EtsErrorUtil::CreateErrorByNativeErr(env, ret), nullptr);
}

void EtsAbilityManager::NativeSetResidentProcessEnabledCheck(ani_env *env, ani_string aniBundleName)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "NativeSetResidentProcessEnabledCheck called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "env null ptr");
        return;
    }

    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName) || bundleName.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "parse bundleName failed, not string");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param bundleName failed, must be a string.");
        return;
    }
}

void EtsAbilityManager::NativeSetResidentProcessEnabled(ani_env *env, ani_string aniBundleName,
    ani_boolean enabled, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "NativeSetResidentProcessEnabled called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "env null ptr");
        return;
    }

    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName) || bundleName.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "parse bundleName failed, not string");
        return;
    }
    bool enableState = (enabled != 0);
    auto amsClient = AAFwk::AbilityManagerClient::GetInstance();
    int32_t ret = ERR_OK;
    if (amsClient == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null amsClient");
        ret = static_cast<int32_t>(AAFwk::INNER_ERR);
    } else {
        ret = amsClient->SetResidentProcessEnabled(bundleName, enableState);
    }

    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "error: %{public}d", ret);
        AppExecFwk::AsyncCallback(env, callbackObj,
            EtsErrorUtil::CreateErrorByNativeErr(env, ret), nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, callbackObj,
        EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
}

void EtsAbilityManager::NativeAcquireShareData(ani_env *env, ani_int aniMissionId, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "NativeAcquireShareData called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "env null ptr");
        return;
    }
    int32_t missionId = aniMissionId;
    ani_ref callbackRef = nullptr;
    env->GlobalReference_Create(callbackObj, &callbackRef);

    auto shareDataCallbackStub = CreateShareDataCallbackStub(env, callbackRef);
    if (shareDataCallbackStub == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null shareDataCallbackStub");
        AppExecFwk::AsyncCallback(env, callbackObj,
            EtsErrorUtil::CreateErrorByNativeErr(env, AAFwk::INNER_ERR), nullptr);
        env->GlobalReference_Delete(callbackRef);
        return;
    }

    auto amsClient = AAFwk::AbilityManagerClient::GetInstance();
    int32_t err = ERR_OK;
    if (amsClient == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null amsClient");
        err = static_cast<int32_t>(AAFwk::INNER_ERR);
    } else {
        err = amsClient->AcquireShareData(missionId, shareDataCallbackStub);
    }
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "error: %{public}d", err);
        AppExecFwk::AsyncCallback(env, callbackObj,
            EtsErrorUtil::CreateErrorByNativeErr(env, err), nullptr);
        env->GlobalReference_Delete(callbackRef);
    }
}

void EtsAbilityManager::NativeUpdateConfiguration(ani_env *env, ani_object configObj, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "NativeUpdateConfiguration called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "env null ptr");
        return;
    }

    AppExecFwk::Configuration changeConfig;
    if (!AppExecFwk::UnwrapConfiguration(env, configObj, changeConfig)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "UnwrapConfiguration failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param config failed, must be a Configuration.");
        return;
    }

    auto appManager = GetAppManagerInstance();
    int32_t errcode = ERR_OK;
    if (appManager == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "appManager is null");
        errcode = static_cast<int32_t>(AAFwk::INNER_ERR);
    } else {
        errcode = appManager->UpdateConfiguration(changeConfig);
    }

    if (errcode != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "UpdateConfiguration failed: %{public}d", errcode);
        AppExecFwk::AsyncCallback(env, callbackObj,
            EtsErrorUtil::CreateErrorByNativeErr(env, errcode), nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, callbackObj,
        EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
}

void EtsAbilityManager::GetExtensionRunningInfos(ani_env *env, ani_int upperLimit, ani_object callback)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call GetExtensionRunningInfos");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }
    std::vector<AAFwk::ExtensionRunningInfo> infos;
    auto errcode = AAFwk::AbilityManagerClient::GetInstance()->GetExtensionRunningInfos(upperLimit, infos);
    if (errcode != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            EtsErrorUtil::CreateErrorByNativeErr(env, errcode), nullptr);
        return;
    }

    ani_object extensionArray = nullptr;
    AbilityManagerEts::WrapExtensionRunningInfoArray(env, extensionArray, infos);
    if (extensionArray == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            EtsErrorUtil::CreateErrorByNativeErr(env,
                static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, callback,
        EtsErrorUtil::CreateErrorByNativeErr(env, errcode), extensionArray);
}

void EtsAbilityManagerRegistryInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call EtsAbilityManagerRegistryInit");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ResetError failed");
    }
    ani_namespace ns = nullptr;
    status = env->FindNamespace(ETS_ABILITY_MANAGER_NAMESPACE, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "FindNamespace abilityManager failed status : %{public}d", status);
        return;
    }
    std::array methods = {
        ani_native_function {
            "nativeGetForegroundUIAbilities", ETS_ABILITY_MANAGER_SIGNATURE_ARRAY,
            reinterpret_cast<void *>(EtsAbilityManager::GetForegroundUIAbilities)
        },
        ani_native_function {
            "getForegroundUIAbilitiesCallback", "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsAbilityManager::GetForegroundUIAbilitiesCallBack)
        },
        ani_native_function {"nativeGetTopAbility", ETS_ABILITY_MANAGER_SIGNATURE_CALLBACK,
            reinterpret_cast<void *>(EtsAbilityManager::GetTopAbility)},
        ani_native_function { "nativeGetAbilityRunningInfos", "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsAbilityManager::GetAbilityRunningInfos) },
        ani_native_function {"nativeGetExtensionRunningInfos", "ILutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsAbilityManager::GetExtensionRunningInfos)},
        ani_native_function { "nativeIsEmbeddedOpenAllowed",
            "Lapplication/Context/Context;Lstd/core/String;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsAbilityManager::IsEmbeddedOpenAllowed) },
        ani_native_function { "nativeQueryAtomicServiceStartupRule",
            "Lapplication/Context/Context;Lstd/core/String;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsAbilityManager::QueryAtomicServiceStartupRule) },
        ani_native_function { "nativeQueryAtomicServiceStartupRuleCheck", "Lapplication/Context/Context;:V",
            reinterpret_cast<void *>(EtsAbilityManager::QueryAtomicServiceStartupRuleCheck) },
        ani_native_function { "nativeOn", nullptr, reinterpret_cast<void *>(EtsAbilityManager::NativeOn) },
        ani_native_function { "nativeOff", nullptr, reinterpret_cast<void *>(EtsAbilityManager::NativeOff) },
        ani_native_function { "nativeNotifyDebugAssertResult",
            nullptr, reinterpret_cast<void *>(EtsAbilityManager::NativeNotifyDebugAssertResult) },
        ani_native_function { "nativeNotifyDebugAssertResultCheck",
            nullptr, reinterpret_cast<void *>(EtsAbilityManager::NativeNotifyDebugAssertResultCheck) },
        ani_native_function { "nativeSetResidentProcessEnabled",
            nullptr, reinterpret_cast<void *>(EtsAbilityManager::NativeSetResidentProcessEnabled) },
        ani_native_function { "nativeSetResidentProcessEnabledCheck",
            nullptr, reinterpret_cast<void *>(EtsAbilityManager::NativeSetResidentProcessEnabledCheck) },
        ani_native_function { "nativeAcquireShareData",
            nullptr, reinterpret_cast<void *>(EtsAbilityManager::NativeAcquireShareData) },
        ani_native_function { "nativeUpdateConfiguration",
            nullptr, reinterpret_cast<void *>(EtsAbilityManager::NativeUpdateConfiguration) }
    };
    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ResetError failed");
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "in AbilityManagerEts.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null vm or result");
        return ANI_INVALID_ARGS;
    }

    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "GetEnv failed, status=%{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsAbilityManagerRegistryInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::ABILITYMGR, "AbilityManagerEts.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AbilityManagerEts
} // namespace OHOS