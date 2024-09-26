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

#include "mock_ability_manager_service.h"

#include "ability_manager_errors.h"
#include "app_utils.h"
#include "hilog_tag_wrapper.h"
#include "permission_verification.h"
#include "process_options.h"

namespace OHOS {
namespace AAFwk {
int32_t AbilityManagerService::CheckProcessOptions(const Want &want, const StartOptions &startOptions, int32_t userId)
{
    if (startOptions.processOptions == nullptr ||
        !ProcessOptions::IsValidProcessMode(startOptions.processOptions->processMode)) {
        return ERR_OK;
    }

    TAG_LOGI(AAFwkTag::ABILITYMGR, "start ability with process options");

    bool isStartupVisibilityHide =
        (startOptions.processOptions->startupVisibility == StartupVisibility::STARTUP_HIDE);
    bool hasStartBackgroundAbilityPermission = PermissionVerification::GetInstance()->
        VerifyStartUIAbilityToHiddenPermission();
    bool canStartupHide = (ProcessOptions::IsNoAttachmentMode(startOptions.processOptions->processMode) &&
        isStartupVisibilityHide && hasStartBackgroundAbilityPermission);
    if (!canStartupHide) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not self application and has no start background ability permission");
        return ERR_NOT_SELF_APPLICATION;
    }

    return ERR_OK;
}

int32_t AbilityManagerService::BlockAllAppStart(bool flag)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");

    if (!AppUtils::GetInstance().IsStartOptionsWithAnimation()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not supported device");
        return ERR_PERMISSION_DENIED;
    }

    if (!PermissionVerification::GetInstance()->VerifyBlockAllAppStartPermission()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Permission verification failed");
        return ERR_PERMISSION_DENIED;
    }

    std::unique_lock<ffrt::mutex> lock(shouldBlockAllAppStartMutex_);
    shouldBlockAllAppStart_ = flag;
    return ERR_OK;
}

bool AbilityManagerService::ShouldBlockAllAppStart()
{
    if (!AppUtils::GetInstance().IsStartOptionsWithAnimation()) {
        return false;
    }

    std::unique_lock<ffrt::mutex> lock(shouldBlockAllAppStartMutex_);
    return shouldBlockAllAppStart_;
}
}  // namespace AAFwk
}  // namespace OHOS
