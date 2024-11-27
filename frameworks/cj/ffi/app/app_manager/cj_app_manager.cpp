/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_app_manager.h"

#include <vector>

#include "ability_manager_interface.h"
#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "app_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "cj_ability_runtime_error.h"
#include "cj_application_context.h"

using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AbilityRuntime {
enum CjAppProcessState {
    STATE_CREATE,
    STATE_FOREGROUND,
    STATE_ACTIVE,
    STATE_BACKGROUND,
    STATE_DESTROY,
};

OHOS::sptr<OHOS::AppExecFwk::IAppMgr> GetAppManagerInstance()
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> appObject = systemAbilityManager->GetSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    return OHOS::iface_cast<OHOS::AppExecFwk::IAppMgr>(appObject);
}

OHOS::sptr<OHOS::AAFwk::IAbilityManager> GetAbilityManagerInstance()
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> abilityObject =
        systemAbilityManager->GetSystemAbility(OHOS::ABILITY_MGR_SERVICE_ID);
    return OHOS::iface_cast<OHOS::AAFwk::IAbilityManager>(abilityObject);
}

CjAppProcessState ConvertToCJAppProcessState(
    const AppExecFwk::AppProcessState &appProcessState, const bool &isFocused)
{
    CjAppProcessState processState;
    switch (appProcessState) {
        case AppExecFwk::AppProcessState::APP_STATE_CREATE:
        case AppExecFwk::AppProcessState::APP_STATE_READY:
            processState = STATE_CREATE;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_FOREGROUND:
            processState = isFocused ? STATE_ACTIVE : STATE_FOREGROUND;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_BACKGROUND:
            processState = STATE_BACKGROUND;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_TERMINATED:
        case AppExecFwk::AppProcessState::APP_STATE_END:
            processState = STATE_DESTROY;
            break;
        default:
            TAG_LOGE(AAFwkTag::APPKIT, "Process state is invalid.");
            processState = STATE_DESTROY;
            break;
    }
    return processState;
}
}  // namespace AbilityRuntime
}  // namespace OHOS

CJ_EXPORT bool FfiAppMgrIsRunningInStabilityTest(int32_t* err)
{
    if (err == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "param err is nullptr!");
        return false;
    }
    auto abilityManager = GetAbilityManagerInstance();
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityManager is nullptr!");
        *err = ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR;
        return false;
    }
    return abilityManager->IsRunningInStabilityTest();
}

CJ_EXPORT bool FfiAppMgrIsRamConstrainedDevice(int32_t* err)
{
    if (err == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "param err is nullptr!");
        return false;
    }
    auto abilityManager = GetAbilityManagerInstance();
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityManager is nullptr!");
        *err = ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR;
        return false;
    }
    return abilityManager->IsRamConstrainedDevice();
}

CJ_EXPORT int32_t FfiAppMgrGetAppMemorySize(int32_t* err)
{
    if (err == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "param err is nullptr!");
        return 0;
    }
    auto abilityManager = GetAbilityManagerInstance();
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityManager is nullptr!");
        *err = ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR;
        return 0;
    }
    return abilityManager->GetAppMemorySize();
}

CJ_EXPORT CArrProcessInformation FfiAppMgrGetRunningProcessInformation(int32_t* err)
{
    CArrProcessInformation processInfos {};
    if (err == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "param err is nullptr!");
        return processInfos;
    }
    auto appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appManager is nullptr!");
        *err = ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR;
        return processInfos;
    }
    std::vector<OHOS::AppExecFwk::RunningProcessInfo> infos;
    auto ret = appManager->GetAllRunningProcesses(infos);
    if (ret != 0) {
        *err = ret;
        TAG_LOGE(AAFwkTag::APPKIT, "GetAllRunningProcesses failed!");
        return processInfos;
    }
    // convert result
    if (!infos.empty()) {
        CProcessInformation* head = static_cast<CProcessInformation*>(malloc(sizeof(*head) * infos.size()));
        if (head == nullptr) {
            *err = ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR;
            return processInfos;
        }
        for (size_t i = 0; i < infos.size(); i++) {
            auto& processInfo = infos[i];
            head[i].processName = CreateCStringFromString(processInfo.processName_);
            head[i].pid = processInfo.pid_;
            head[i].uid = processInfo.uid_;
            head[i].bundleNames.head = VectorToCArrString(processInfo.bundleNames);
            head[i].bundleNames.size = (processInfo.bundleNames).size();
            head[i].state = ConvertToCJAppProcessState(processInfo.state_, processInfo.isFocused);
            head[i].bundleType = processInfo.bundleType;
            head[i].appCloneIndex = processInfo.appCloneIndex;
        }
        processInfos.size = infos.size();
        processInfos.head = head;
    }
    return processInfos;
}
