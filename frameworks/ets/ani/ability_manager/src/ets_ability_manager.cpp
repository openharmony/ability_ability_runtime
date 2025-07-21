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
#include "ani_base_context.h"
#include "ani_common_ability_state_data.h"
#include "ani_common_want.h"
#include "ets_ability_manager_utils.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* ETS_ABILITY_MANAGER_NAMESPACE = "L@ohos/app/ability/abilityManager/abilityManager;";
constexpr const char* ETS_ABILITY_MANAGER_SIGNATURE_ARRAY = ":Lescompat/Array;";
constexpr const char* ETS_ABILITY_MANAGER_SIGNATURE_CALLBACK = "Lutils/AbilityUtils/AsyncCallbackWrapper;:V";
constexpr int32_t ERR_FAILURE = -1;
}

sptr<AppExecFwk::IAbilityManager> GetAbilityManagerInstance()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> abilityManagerObj =
        systemAbilityManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    return iface_cast<AppExecFwk::IAbilityManager>(abilityManagerObj);
}
static ani_object GetForegroundUIAbilities(ani_env *env)
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

static void GetTopAbility(ani_env *env, ani_object callback)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call GetTopAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }
#ifdef ENABLE_ERRCODE
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not system app");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return;
    }
#endif
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

void GetAbilityRunningInfos(ani_env *env, ani_object callback)
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

void IsEmbeddedOpenAllowed(ani_env *env, ani_object contextObj, ani_string aniAppId, ani_object callbackObj)
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
            reinterpret_cast<void *>(GetForegroundUIAbilities)
        },
        ani_native_function {"nativeGetTopAbility", ETS_ABILITY_MANAGER_SIGNATURE_CALLBACK,
            reinterpret_cast<void *>(GetTopAbility)},
        ani_native_function { "nativeGetAbilityRunningInfos", "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(GetAbilityRunningInfos) },
        ani_native_function { "nativeIsEmbeddedOpenAllowed",
            "Lapplication/Context/Context;Lstd/core/String;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(IsEmbeddedOpenAllowed) },
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