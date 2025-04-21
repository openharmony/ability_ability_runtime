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

#include "sts_ability_manager.h"

#include "ability_business_error.h"
#include "ability_manager_errors.h"
#include "ability_runtime_error_util.h"
#include "ani_common_ability_state_data.h"
#include "ani_common_want.h"
#include "hilog_tag_wrapper.h"
#include "ability_manager_interface.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "sts_error_utils.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AbilityManagerSts {

const int32_t ERR_FAILURE = -1;
const char *INVOKE_METHOD_NAME = "invoke";

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
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call GetForegroundUIAbilities");

    sptr<AppExecFwk::IAbilityManager> abilityManager = GetAbilityManagerInstance();
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "abilityManager is null");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    std::vector<AppExecFwk::AbilityStateData> list;
    int32_t ret = abilityManager->GetForegroundUIAbilities(list);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed: ret=%{public}d", ret);
        AbilityRuntime::AbilityErrorCode code = AbilityRuntime::GetJsErrorCodeByNativeError(ret);
        AbilityRuntime::ThrowStsError(env, code);
        return nullptr;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "GetForegroundUIAbilities succeeds, list.size=%{public}zu", list.size());
    ani_object aniArray = AppExecFwk::CreateAniAbilityStateDataArray(env, list);
    if (aniArray == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null aniArray");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return nullptr;
    }
    return aniArray;
}

static void GetTopAbility(ani_env *env, ani_object callback)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call GetTopAbility");
#ifdef ENABLE_ERRCODE
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not system app");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return
    }
#endif
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    sptr<AppExecFwk::IAbilityManager> abilityManager = GetAbilityManagerInstance();
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "abilityManager is nullptr");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::ElementName elementName = abilityManager->GetTopAbility();
    std::string abilityName = elementName.GetAbilityName();
    std::string bundleName = elementName.GetBundleName();
    TAG_LOGI(AAFwkTag::ABILITYMGR, "GetTopAbility succeeds, abilityName = %{public}s"
        "bundleName = %{public}s", abilityName.c_str(), bundleName.c_str());
    int resultCode = 0;
    ani_object ElementNameobj = AppExecFwk::WrapElementName(env, elementName);
    if (ElementNameobj == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ElementNameobj");
        resultCode = ERR_FAILURE;
    }
    ani_ref callbackRef = nullptr;
    auto status = env->GlobalReference_Create(callback, &callbackRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Create Gloabl ref for abilitymanager failed %{public}d", status);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        ElementNameobj);
    return;
}

void StsAbilityManagerRegistryInit(ani_env *env)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call StsAbilityManagerRegistryInit");

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }

    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ResetError failed");
    }

    ani_namespace ns;
    status = env->FindNamespace("L@ohos/app/ability/abilityManager/abilityManager;", &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "FindNamespace abilityManager failed status : %{public}d", status);
        return;
    }

    std::array methods = {
        ani_native_function {
            "nativeGetForegroundUIAbilities",
            nullptr,
            reinterpret_cast<void *>(GetForegroundUIAbilities)
        },
        ani_native_function {"nativeGetTopAbility", nullptr, reinterpret_cast<void *>(GetTopAbility)},
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
    TAG_LOGI(AAFwkTag::ABILITYMGR, "in AbilityManagerSts.ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null vm");
        return ANI_NOT_FOUND;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "GetEnv failed, status=%{public}d", status);
        return ANI_NOT_FOUND;
    }

    StsAbilityManagerRegistryInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilityManagerSts.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AbilityManagerSts
} // namespace OHOS