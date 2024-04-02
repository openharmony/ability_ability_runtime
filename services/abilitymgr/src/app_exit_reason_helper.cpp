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

#include "app_exit_reason_helper.h"

#include <string>
#include <vector>

#include "ability_util.h"
#include "ability_manager_errors.h"
#include "app_exit_reason_data_manager.h"
#include "app_scheduler.h"
#include "bundle_constants.h"
#include "bundle_mgr_interface.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "scene_board_judgement.h"
#include "singleton.h"

namespace OHOS {
namespace AAFwk {
namespace {
    constexpr int32_t U0_USER_ID = 0;
}
AppExitReasonHelper::AppExitReasonHelper(std::shared_ptr<UIAbilityLifecycleManager> &uiAbilityLifecycleManager,
    std::unordered_map<int, std::shared_ptr<MissionListManager>> &missionListManagers, ffrt::mutex &managersMutex,
    std::shared_ptr<AbilityConnectManager> &connectManager)
    : uiAbilityLifecycleManager_(uiAbilityLifecycleManager), missionListManagers_(missionListManagers),
      managersMutex_(managersMutex), connectManager_(connectManager)
{}

void AppExitReasonHelper::SetCurrentMissionListManager(
    const std::shared_ptr<MissionListManager> currentMissionListManager)
{
    currentMissionListManager_ = currentMissionListManager;
}

int32_t AppExitReasonHelper::RecordAppExitReason(const ExitReason &exitReason)
{
    if (!IsExitReasonValid(exitReason)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Force exit reason invalid.");
        return ERR_INVALID_VALUE;
    }

    auto bms = AbilityUtil::GetBundleManagerHelper();
    CHECK_POINTER_AND_RETURN(bms, ERR_NULL_OBJECT);
    std::string bundleName;
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    if (IN_PROCESS_CALL(bms->GetNameForUid(callerUid, bundleName)) != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Get Bundle Name failed.");
        return GET_BUNDLE_INFO_FAILED;
    }

    std::vector<std::string> abilityList;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        CHECK_POINTER_AND_RETURN(uiAbilityLifecycleManager_, ERR_NULL_OBJECT);
        uiAbilityLifecycleManager_->GetActiveAbilityList(bundleName, abilityList);
    } else {
        CHECK_POINTER_AND_RETURN(currentMissionListManager_, ERR_NULL_OBJECT);
        currentMissionListManager_->GetActiveAbilityList(bundleName, abilityList);
    }

    if (abilityList.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Active abilityLists empty.");
        return ERR_GET_ACTIVE_ABILITY_LIST_EMPTY;
    }

    return DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->SetAppExitReason(
        bundleName, abilityList, exitReason);
}

int32_t AppExitReasonHelper::RecordProcessExitReason(const int32_t pid, const ExitReason &exitReason)
{
    std::string bundleName;
    int32_t uid;
    DelayedSingleton<AppScheduler>::GetInstance()->GetBundleNameByPid(pid, bundleName, uid);
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Get bundle name by pid failed.");
        return GET_BUNDLE_INFO_FAILED;
    }
    return RecordProcessExitReason(pid, exitReason, bundleName, uid);
}

int32_t AppExitReasonHelper::RecordProcessExitReason(const int32_t pid, const ExitReason &exitReason,
    const std::string bundleName, const int32_t uid)
{
    if (!IsExitReasonValid(exitReason)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Force exit reason invalid.");
        return ERR_INVALID_VALUE;
    }

    int32_t targetUserId = uid / AppExecFwk::Constants::BASE_USER_RANGE;
    std::vector<std::string> abilityLists;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        CHECK_POINTER_AND_RETURN(uiAbilityLifecycleManager_, ERR_NULL_OBJECT);
        uiAbilityLifecycleManager_->GetActiveAbilityList(bundleName, abilityLists, targetUserId, pid);
    } else if (targetUserId == U0_USER_ID) {
        GetActiveAbilityListByU0(bundleName, abilityLists, pid);
    } else {
        GetActiveAbilityListByUser(bundleName, abilityLists, targetUserId, pid);
    }
    if (!abilityLists.empty()) {
        return DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->SetAppExitReason(
            bundleName, abilityLists, exitReason);
    }

    return RecordProcessExtensionExitReason(pid, bundleName, exitReason);
}

void AppExitReasonHelper::DeleteAppExitReasonOfExtension(const std::string &bundleName)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Called.");
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Invalid bundle name.");
        return;
    }
    if (connectManager_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Connect manager is nullptr.");
        return;
    }
    std::vector<std::string> extensionList;
    int32_t resultCode = connectManager_->GetActiveUIExtensionList(bundleName, extensionList);
    if (resultCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Get extensionList error.");
        return;
    }

    if (extensionList.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ExtensionList is empty.");
        return;
    }

    for (size_t i = 0; i < extensionList.size(); i++) {
        DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->DeleteAppExitReasonOfExtension(
            bundleName, extensionList[i]);
    }
}

int32_t AppExitReasonHelper::RecordProcessExtensionExitReason(
    const int32_t pid, const std::string &bundleName, const ExitReason &exitReason)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Called.");
    if (pid <= NO_PID) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Input pid is invalid value.");
        return ERR_INVALID_VALUE;
    }
    CHECK_POINTER_AND_RETURN(connectManager_, ERR_NULL_OBJECT);
    std::vector<std::string> extensionList;
    int32_t resultCode = connectManager_->GetActiveUIExtensionList(pid, extensionList);
    if (resultCode != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "ResultCode: %{public}d", resultCode);
        return ERR_GET_ACTIVE_EXTENSION_LIST_EMPTY;
    }

    if (extensionList.empty()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "ExtensionList is empty.");
        return ERR_GET_ACTIVE_EXTENSION_LIST_EMPTY;
    }

    auto appExitReasonDataMgr = DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance();
    if (appExitReasonDataMgr == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Get app exit reason data mgr instance is nullptr.");
        return ERR_INVALID_VALUE;
    }

    return appExitReasonDataMgr->SetUIExtensionAbilityBeFinishReason(bundleName, extensionList, exitReason);
}

void AppExitReasonHelper::GetActiveAbilityListByU0(const std::string bundleName,
    std::vector<std::string> &abilityLists, const int32_t pid)
{
    std::lock_guard lock(managersMutex_);
    for (auto item: missionListManagers_) {
        if (!item.second) {
            continue;
        }
        std::vector<std::string> abilityList;
        item.second->GetActiveAbilityList(bundleName, abilityList, pid);
        if (!abilityList.empty()) {
            abilityLists.insert(abilityLists.end(), abilityList.begin(), abilityList.end());
        }
    }
}

void AppExitReasonHelper::GetActiveAbilityListByUser(const std::string bundleName,
    std::vector<std::string> &abilityLists, const int32_t targetUserId, const int32_t pid)
{
    auto listManager = GetListManagerByUserId(targetUserId);
    if (listManager) {
        listManager->GetActiveAbilityList(bundleName, abilityLists, pid);
    }
}

std::shared_ptr<MissionListManager> AppExitReasonHelper::GetListManagerByUserId(int32_t userId)
{
    std::lock_guard<ffrt::mutex> lock(managersMutex_);
    auto it = missionListManagers_.find(userId);
    if (it != missionListManagers_.end()) {
        return it->second;
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "Failed to get MissionListManager. UserId = %{public}d", userId);
    return nullptr;
}

bool AppExitReasonHelper::IsExitReasonValid(const ExitReason &exitReason)
{
    const Reason reason = exitReason.reason;
    return reason >= REASON_MIN || reason <= REASON_MAX;
}
}  // namespace AppExecFwk
}  // namespace OHOS
