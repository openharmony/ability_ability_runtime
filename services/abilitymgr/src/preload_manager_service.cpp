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

#include "preload_manager_service.h"

#include "ability_manager_errors.h"
#include "ability_manager_service.h"
#include "ability_util.h"
#include "app_scheduler.h"
#include "app_utils.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "permission_verification.h"
#include "process_options.h"
#include "start_options.h"

namespace OHOS {
namespace AAFwk {
PreloadManagerService &PreloadManagerService::GetInstance()
{
    static PreloadManagerService instance;
    return instance;
}

PreloadManagerService::PreloadManagerService() {}

PreloadManagerService::~PreloadManagerService() {}

int32_t PreloadManagerService::PreloadApplication(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    if (!AppUtils::GetInstance().IsPreloadApplicationEnabled() || appIndex != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "preload application not supported");
        return ERR_CAPABILITY_NOT_SUPPORT;
    }
    if (!PermissionVerification::GetInstance()->VerifyPreloadApplicationPermission()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "no preload permission");
        return ERR_PERMISSION_DENIED;
    }
    userId = DelayedSingleton<AbilityManagerService>::GetInstance()->GetValidUserId(userId);
    if (!DelayedSingleton<AbilityManagerService>::GetInstance()->JudgeMultiUserConcurrency(userId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "multi-user non-concurrent unsatisfied:%{public}d", ERR_CROSS_USER);
        return ERR_CROSS_USER;
    }

    bool isExist = false;
    int32_t ret = ERR_OK;
    CHECK_TRUE_RETURN_RET((ret = DelayedSingleton<AppScheduler>::GetInstance()->CheckPreloadAppRecordExist(
        bundleName, userId, appIndex, isExist)) != ERR_OK, ret, "CheckPreloadAppRecordExist failed");
    CHECK_TRUE_RETURN_RET(isExist, ERR_PRELOAD_APP_RECORD_ALREADY_EXIST, "already started");

    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    CHECK_POINTER_AND_RETURN(bundleMgrHelper, INNER_ERR);

    Want launchWant;
    auto errCode = IN_PROCESS_CALL(bundleMgrHelper->GetLaunchWantForBundle(bundleName, launchWant, userId));
    if (errCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "getLaunchWantForBundle returns %{public}d", errCode);
        return errCode;
    }

    AppExecFwk::AbilityInfo abilityInfo;
    CHECK_TRUE_RETURN_RET(!IN_PROCESS_CALL(bundleMgrHelper->QueryAbilityInfo(launchWant,
        AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION, userId, abilityInfo)),
        RESOLVE_ABILITY_ERR, "failed to get abilityInfo");
    AppExecFwk::AppPreloadPhase appPreloadPhase = abilityInfo.applicationInfo.appPreloadPhase;
    if (appPreloadPhase == AppExecFwk::AppPreloadPhase::DEFAULT) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "preload phase not set");
        return ERR_APP_PRELOAD_PHASE_UNSET;
    }
    if (appPreloadPhase <= AppExecFwk::AppPreloadPhase::ABILITY_STAGE_CREATED) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "preload to phase:%{public}d", static_cast<int32_t>(appPreloadPhase));
        AppExecFwk::PreloadPhase preloadPhase = static_cast<AppExecFwk::PreloadPhase>(appPreloadPhase);
        return DelayedSingleton<AppScheduler>::GetInstance()->PreloadApplicationByPhase(
            bundleName, userId, appIndex, preloadPhase);
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "preload to window stage create");
    StartOptions options;
    options.processOptions = std::make_shared<ProcessOptions>();
    options.processOptions->startupVisibility = StartupVisibility::STARTUP_HIDE;
    options.processOptions->isPreloadStart = true;
    return DelayedSingleton<AbilityManagerService>::GetInstance()->StartAbility(launchWant, options, nullptr, userId);
}
}  // namespace AAFwk
}  // namespace OHOS
