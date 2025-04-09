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

#include "sts_app_manager.h"

#include "hilog_tag_wrapper.h"
#include "ability_manager_client.h"
#include "ability_manager_interface.h"
#include "app_mgr_constants.h"
#include "app_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppManagerSts {
thread_local std::unique_ptr<AbilityRuntime::STSNativeReference> stsReference;

OHOS::sptr<OHOS::AppExecFwk::IAppMgr> GetAppManagerInstance()
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> appObject = systemAbilityManager->GetSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    return OHOS::iface_cast<OHOS::AppExecFwk::IAppMgr>(appObject);
}

static void PreloadApplication(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_string bundleName, ani_int userId, ani_int mode, ani_int appIndex)
{
    std::string bundleNameStr;
    ani_size sz {};
    env->String_GetUTF8Size(bundleName, &sz);
    bundleNameStr.resize(sz + 1);
    env->String_GetUTF8SubString(bundleName, 0, sz, bundleNameStr.data(), bundleNameStr.size(), &sz);

    sptr<OHOS::AppExecFwk::IAppMgr> appMgr = GetAppManagerInstance();
    if (appMgr == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "appMgr is null");
        return;
    }
    appMgr->PreloadApplication(bundleNameStr, userId, static_cast<AppExecFwk::PreloadMode>(mode), appIndex);
}

void StsAppManagerRegistryInit(ani_env *env)
{
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed");
    }

    ani_namespace ns;
    status = env->FindNamespace("L@ohos/app/ability/appManager/appManager;", &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindNamespace appManager failed status : %{public}d", status);
        return;
    }

    std::array kitFunctions = {
        ani_native_function {"nativePreloadApplication", nullptr, reinterpret_cast<void *>(PreloadApplication)},
    };

    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }

    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed");
    }
}
} // namespace AbilityDelegatorSts
} // namespace OHOS