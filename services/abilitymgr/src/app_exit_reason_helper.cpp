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

#include "accesstoken_kit.h"
#include "app_exit_reason_data_manager.h"
#include "bundle_mgr_helper.h"
#include "os_account_manager_wrapper.h"
#include "scene_board_judgement.h"

namespace OHOS {
namespace AAFwk {
namespace {
    constexpr int32_t U0_USER_ID = 0;
}

AppExitReasonHelper::AppExitReasonHelper(std::shared_ptr<SubManagersHelper> subManagersHelper)
    : subManagersHelper_(subManagersHelper) {}

static int32_t GetAppIdentify(const ExitReason &exitReason, int32_t &pid, int32_t &uid, std::string &bundleName,
    int32_t &appIndex, AppExecFwk::RunningProcessInfo &processInfo)
{
    ErrCode ret = ERR_OK;
    if (pid <= 0) {
        uid = IPCSkeleton::GetCallingUid();
        ret = IN_PROCESS_CALL(AbilityUtil::GetBundleManagerHelper()->GetNameAndIndexForUid(uid, bundleName, appIndex));
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "failed, ret:%{public}d", ret);
            return ret;
        }
        if (exitReason.reason != Reason::REASON_CPP_CRASH) {
            pid = IPCSkeleton::GetCallingPid();
        }
    } else {
        DelayedSingleton<AppScheduler>::GetInstance()->GetRunningProcessInfoByPid(static_cast<pid_t>(pid),
            processInfo);
        uid = processInfo.uid_;
        if (processInfo.bundleNames.size() == 1) {
            bundleName = processInfo.bundleNames[0];
        }
        appIndex = processInfo.appCloneIndex;
    }
    return ret;
}

int32_t AppExitReasonHelper::RecordAppExitReason(const ExitReason &exitReason, int32_t pid, bool withKillMsg)
{
    if (!IsExitReasonValid(exitReason)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "exit reason invalid");
        return ERR_INVALID_VALUE;
    }
    ErrCode ret = ERR_OK;
    auto uid = -1;
    std::string bundleName = "";
    int32_t appIndex = 0;
    AppExecFwk::RunningProcessInfo processInfo;
    ret = GetAppIdentify(exitReason, pid, uid, bundleName, appIndex, processInfo);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "GetAppIdentify failed, ret: %{public}d", ret);
        return ret;
    }
    
    ret = RecordProcessExtensionExitReason(pid, bundleName, exitReason, processInfo, withKillMsg);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "record extension reason failed, code: %{public}d", ret);
    }
    CHECK_POINTER_AND_RETURN(subManagersHelper_, ERR_NULL_OBJECT);
    std::vector<std::string> abilityList;
    int32_t getActiveAbilityListRet = GetActiveAbilityList(uid, abilityList);
    if (getActiveAbilityListRet != ERR_OK) {
        return getActiveAbilityListRet;
    }
    ret = DelayedSingleton<AppScheduler>::GetInstance()->NotifyAppMgrRecordExitReason(pid, exitReason.reason,
        exitReason.exitMsg);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed,code: %{public}d", ret);
    }
    if (abilityList.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "abilityLists empty");
        return ERR_GET_ACTIVE_ABILITY_LIST_EMPTY;
    }
    int32_t userId;
    int32_t getOsAccountRet = DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->
        GetOsAccountLocalIdFromUid(uid, userId);
    if (getOsAccountRet != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get GetOsAccountLocalIdFromUid failed. ret: %{public}d", getOsAccountRet);
        return ERR_INVALID_VALUE;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR,
        "userId: %{public}d, bundleName: %{public}s, appIndex: %{public}d", userId, bundleName.c_str(), appIndex);
    uint32_t accessTokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appIndex);
    return DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->SetAppExitReason(bundleName,
        accessTokenId, abilityList, exitReason, processInfo, withKillMsg);
}

int32_t AppExitReasonHelper::RecordProcessExitReason(const int32_t pid, const ExitReason &exitReason)
{
    AppExecFwk::ApplicationInfo application;
    bool debug = false;
    auto ret = IN_PROCESS_CALL(DelayedSingleton<AppScheduler>::GetInstance()->GetApplicationInfoByProcessID(pid,
        application, debug));
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "getApplicationInfoByProcessID failed");
        return ret;
    }
    auto bundleName = application.bundleName;
    AppExecFwk::RunningProcessInfo processInfo;
    if (pid > 0) {
        DelayedSingleton<AppScheduler>::GetInstance()->GetRunningProcessInfoByPid(
            static_cast<pid_t>(pid), processInfo);
    }
    int32_t resultCode = RecordProcessExtensionExitReason(pid, bundleName, exitReason, processInfo, false);
    if (resultCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "record Reason failed, code: %{public}d", resultCode);
    }

    return RecordProcessExitReason(pid, bundleName, application.uid, application.accessTokenId, exitReason,
        processInfo);
}

int32_t AppExitReasonHelper::RecordAppExitReason(const std::string &bundleName, int32_t uid, int32_t appIndex,
    const ExitReason &exitReason)
{
    int32_t userId;
    int32_t getOsAccountRet = DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->
        GetOsAccountLocalIdFromUid(uid, userId);
    if (getOsAccountRet != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get GetOsAccountLocalIdFromUid failed. ret: %{public}d", getOsAccountRet);
        return ERR_INVALID_VALUE;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR,
        "userId: %{public}d, bundleName: %{public}s, appIndex: %{public}d", userId, bundleName.c_str(), appIndex);
    uint32_t accessTokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appIndex);
    AppExecFwk::RunningProcessInfo processInfo;
    return RecordProcessExitReason(NO_PID, bundleName, uid, accessTokenId, exitReason, processInfo);
}

int32_t AppExitReasonHelper::RecordProcessExitReason(const int32_t pid, const std::string bundleName,
    const int32_t uid, const uint32_t accessTokenId, const ExitReason &exitReason,
    const AppExecFwk::RunningProcessInfo &processInfo)
{
    if (!IsExitReasonValid(exitReason)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "reason invalid");
        return ERR_INVALID_VALUE;
    }

    int32_t targetUserId;
    int32_t getOsAccountRet = DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->
        GetOsAccountLocalIdFromUid(uid, targetUserId);
    if (getOsAccountRet != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get GetOsAccountLocalIdFromUid failed. ret: %{pubilc}d", getOsAccountRet);
        return ERR_INVALID_VALUE;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "targetUserId: %{public}d", targetUserId);
    std::vector<std::string> abilityLists;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        GetActiveAbilityListFromUIAbilityManager(uid, abilityLists, pid);
    } else  {
        GetActiveAbilityList(uid, abilityLists, pid);
    }

    auto ret = DelayedSingleton<AppScheduler>::GetInstance()->NotifyAppMgrRecordExitReason(pid, exitReason.reason,
        exitReason.exitMsg);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed:%{public}d", ret);
    }

    if (abilityLists.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "active abilityLists empty");
        return ERR_GET_ACTIVE_ABILITY_LIST_EMPTY;
    }
    return DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->SetAppExitReason(bundleName,
        accessTokenId, abilityLists, exitReason, processInfo, false);
}

int32_t AppExitReasonHelper::RecordProcessExtensionExitReason(
    const int32_t pid, const std::string &bundleName, const ExitReason &exitReason,
    const AppExecFwk::RunningProcessInfo &processInfo, bool withKillMsg)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    CHECK_POINTER_AND_RETURN(subManagersHelper_, ERR_NULL_OBJECT);
    auto connectManager = subManagersHelper_->GetCurrentConnectManager();
    CHECK_POINTER_AND_RETURN(connectManager, ERR_NULL_OBJECT);
    std::vector<std::string> extensionList;
    int32_t resultCode = ERR_OK;
    if (pid <= NO_PID) {
        resultCode = connectManager->GetActiveUIExtensionList(bundleName, extensionList);
    } else {
        resultCode = connectManager->GetActiveUIExtensionList(pid, extensionList);
    }
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
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null appExitReasonDataMgr");
        return ERR_INVALID_VALUE;
    }

    return appExitReasonDataMgr->SetUIExtensionAbilityExitReason(bundleName, extensionList, exitReason,
        processInfo, withKillMsg);
}

void AppExitReasonHelper::CacheAppExitReason(uint32_t accessTokenId, const AAFwk::LastExitDetailInfo &exitInfo,
    const std::string &bundleName, const std::vector<std::string> &abilityNames,
    const std::vector<std::string> &uiExtensionNames)
{
    auto appExitReasonDataMgr = DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance();
    if (appExitReasonDataMgr == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null appExitReasonDataMgr");
        return;
    }
    ExitReason exitReason = {};
    AppExecFwk::RunningProcessInfo processInfo = {};
    processInfo.pid_ = exitInfo.pid;
    processInfo.uid_ = exitInfo.uid;
    processInfo.rssValue = exitInfo.rss;
    processInfo.pssValue = exitInfo.pss;
    processInfo.processName_ = exitInfo.processName;
    appExitReasonDataMgr->SetUIExtensionAbilityExitReason(bundleName, uiExtensionNames,
        exitReason, processInfo, false);
    appExitReasonDataMgr->SetAppExitReason(bundleName, accessTokenId, abilityNames, exitReason,
        processInfo, false, true);
}

void AppExitReasonHelper::GetActiveAbilityList(int32_t uid, std::vector<std::string> &abilityLists,
    const int32_t pid)
{
    int32_t targetUserId;
    int32_t getOsAccountRet = DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->
        GetOsAccountLocalIdFromUid(uid, targetUserId);
    if (getOsAccountRet != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get GetOsAccountLocalIdFromUid failed. ret: %{public}d", getOsAccountRet);
        return;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "targetUserId: %{public}d", targetUserId);
    CHECK_POINTER(subManagersHelper_);
    if (targetUserId == U0_USER_ID) {
        auto missionListManagers = subManagersHelper_->GetMissionListManagers();
        for (auto& item: missionListManagers) {
            CHECK_POINTER_CONTINUE(item.second);
            std::vector<std::string> abilityList;
            item.second->GetActiveAbilityList(uid, abilityList, pid);
            if (!abilityList.empty()) {
                abilityLists.insert(abilityLists.end(), abilityList.begin(), abilityList.end());
            }
        }
        return;
    }

    auto listManager = subManagersHelper_->GetMissionListManagerByUserId(targetUserId);
    CHECK_POINTER(listManager);
    listManager->GetActiveAbilityList(uid, abilityLists, pid);
}

void AppExitReasonHelper::GetActiveAbilityListFromUIAbilityManager(int32_t uid, std::vector<std::string> &abilityLists,
    const int32_t pid)
{
    CHECK_POINTER(subManagersHelper_);
    int32_t targetUserId;
    int32_t getOsAccountRet = DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->
        GetOsAccountLocalIdFromUid(uid, targetUserId);
    if (getOsAccountRet != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get GetOsAccountLocalIdFromUid failed. ret: %{public}d", getOsAccountRet);
        return;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "targetUserId: %{public}d", targetUserId);
    if (targetUserId == U0_USER_ID) {
        auto uiAbilityManagers = subManagersHelper_->GetUIAbilityManagers();
        for (auto& item: uiAbilityManagers) {
            CHECK_POINTER_CONTINUE(item.second);
            std::vector<std::string> abilityList;
            item.second->GetActiveAbilityList(uid, abilityList, pid);
            if (!abilityList.empty()) {
                abilityLists.insert(abilityLists.end(), abilityList.begin(), abilityList.end());
            }
        }
        return;
    }

    auto uiAbilityManager = subManagersHelper_->GetUIAbilityManagerByUserId(targetUserId);
    CHECK_POINTER(uiAbilityManager);
    uiAbilityManager->GetActiveAbilityList(uid, abilityLists, pid);
}

bool AppExitReasonHelper::IsExitReasonValid(const ExitReason &exitReason)
{
    const Reason reason = exitReason.reason;
    return reason >= REASON_MIN && reason <= REASON_MAX;
}

int32_t AppExitReasonHelper::GetActiveAbilityList(int32_t uid, std::vector<std::string> &abilityList)
{
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        auto uiAbilityManager = subManagersHelper_->GetUIAbilityManagerByUid(uid);
        CHECK_POINTER_AND_RETURN(uiAbilityManager, ERR_NULL_OBJECT);
        uiAbilityManager->GetActiveAbilityList(uid, abilityList);
    } else {
        auto missionListManager = subManagersHelper_->GetMissionListManagerByUid(uid);
        CHECK_POINTER_AND_RETURN(missionListManager, ERR_NULL_OBJECT);
        missionListManager->GetActiveAbilityList(uid, abilityList);
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
