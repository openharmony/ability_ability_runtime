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

#include "keep_alive_process_manager.h"

#include "ability_util.h"
#include "ffrt.h"
#include "keep_alive_utils.h"
#include "main_element_utils.h"
#include "process_options.h"

namespace OHOS {
namespace AAFwk {
constexpr int32_t CREATE_STATUS_BAR_TIMEOUT_SECONDS = 5; // 5s

KeepAliveProcessManager::KeepAliveProcessManager()
{
    abilityKeepAliveService_ = std::make_shared<AbilityRuntime::AbilityKeepAliveService>();
}

KeepAliveProcessManager::~KeepAliveProcessManager()
{
    abilityKeepAliveService_.reset();
    abilityKeepAliveService_ = nullptr;
}

void KeepAliveProcessManager::StartKeepAliveProcessWithMainElement(std::vector<AppExecFwk::BundleInfo> &bundleInfos,
    int32_t userId)
{
    for (const auto &bundleInfo : bundleInfos) {
        StartKeepAliveProcessWithMainElementPerBundle(bundleInfo, userId);
    }
}

void KeepAliveProcessManager::StartKeepAliveProcessWithMainElementPerBundle(const AppExecFwk::BundleInfo &bundleInfo,
    int32_t userId)
{
    if (abilityKeepAliveService_ == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "abilityKeepAliveService_ null");
        return;
    }
    bool keepAliveEnable = false;
    (void)abilityKeepAliveService_->GetKeepAliveProcessEnable(bundleInfo.name, userId, keepAliveEnable);
    if (!keepAliveEnable) {
        return;
    }

    std::string mainElementName;
    if (!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle has no main uiability");
        return;
    }
    auto ret = StartAbility(bundleInfo.name, bundleInfo.entryModuleName, mainElementName, userId);
    if (ret != ERR_OK) {
        AddFailedKeepAliveAbility(bundleInfo.name, bundleInfo.entryModuleName, mainElementName, userId);
        return;
    }

    ffrt::submit([self = shared_from_this(), bundleInfo, mainElementName, userId]() {
        self->AfterStartKeepAliveApp(bundleInfo, mainElementName, userId);
    });
}

int32_t KeepAliveProcessManager::StartAbility(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, int32_t userId)
{
    Want want;
    want.SetElementName(bundleName, abilityName);
    TAG_LOGI(AAFwkTag::KEEP_ALIVE, "call, bundleName: %{public}s, mainElement: %{public}s",
        bundleName.c_str(), abilityName.c_str());
    StartOptions options;
    options.processOptions = std::make_shared<ProcessOptions>();
    options.processOptions->processMode = ProcessMode::ATTACH_TO_STATUS_BAR_ITEM;
    options.processOptions->startupVisibility = StartupVisibility::STARTUP_HIDE;
    auto ret = IN_PROCESS_CALL(DelayedSingleton<AbilityManagerService>::GetInstance()->StartAbility(want,
        options, nullptr, userId, DEFAULT_INVAL_VALUE));
    MainElementUtils::UpdateMainElement(bundleName, moduleName, abilityName, true, userId);
    return ret;
}

void KeepAliveProcessManager::AfterStartKeepAliveApp(const AppExecFwk::BundleInfo &bundleInfo,
    const std::string &mainElementName, int32_t userId)
{
    uint32_t accessTokenId = 0;
    MainElementUtils::GetMainUIAbilityAccessTokenId(bundleInfo, mainElementName, accessTokenId);
    bool isCreated = false;
    std::shared_ptr<bool> isCanceled = std::make_shared<bool>(false);
    ffrt::condition_variable taskCv;
    ffrt::mutex taskMutex;
    ffrt::submit([&isCreated, &taskCv, &taskMutex, isCanceled, accessTokenId,
        abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance()]() {
        if (accessTokenId == 0) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "access token id is invalid");
            std::lock_guard<ffrt::mutex> lock(taskMutex);
            *isCanceled = true;
            taskCv.notify_all();
            return;
        }
        while (abilityMgr && !abilityMgr->IsInStatusBar(accessTokenId)) {
            {
                std::lock_guard<ffrt::mutex> lock(taskMutex);
                if (*isCanceled) {
                    TAG_LOGI(AAFwkTag::KEEP_ALIVE, "canceled in the middle");
                    return;
                }
            }
            usleep(REPOLL_TIME_MICRO_SECONDS);
        }
        {
            std::lock_guard<ffrt::mutex> lock(taskMutex);
            isCreated = true;
        }
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "start notify");
        taskCv.notify_all();
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "finished checking status bar");
    });
    auto condition = [&isCreated, &isCanceled] { return (isCreated || isCanceled); };
    {
        std::unique_lock<ffrt::mutex> lock(taskMutex);
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "wait for condition");
        if (!taskCv.wait_for(lock, std::chrono::seconds(CREATE_STATUS_BAR_TIMEOUT_SECONDS), condition)) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "attach status bar timeout");
            *isCanceled = true;
        }
    }
    if (isCreated) {
        return;
    }
    SetApplicationKeepAlive(bundleInfo.name, userId, false, true);
}

int32_t KeepAliveProcessManager::SetApplicationKeepAlive(const std::string &bundleName,
    int32_t userId, bool updateEnable, bool isByEDM)
{
    CHECK_TRUE_RETURN_RET(bundleName.empty(), INVALID_PARAMETERS_ERR, "input parameter error");

    auto bms = AbilityUtil::GetBundleManagerHelper();
    CHECK_POINTER_AND_RETURN(bms, INNER_ERR);

    auto abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance();
    CHECK_POINTER_AND_RETURN(abilityMgr, INNER_ERR);
    AppExecFwk::BundleInfo bundleInfo;
    if (userId < 0) {
        userId = abilityMgr->GetUserId();
    }

    if (!IN_PROCESS_CALL(bms->GetBundleInfo(
        bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId))) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "get bundle info failed");
        return ERR_INVALID_VALUE;
    }

    CHECK_POINTER_AND_RETURN(abilityKeepAliveService_, INNER_ERR);
    bool localEnable = false;
    auto result = abilityKeepAliveService_->GetKeepAliveProcessEnable(bundleName, userId, localEnable);
    CHECK_TRUE_RETURN_RET((result != ERR_OK && result != ERR_NAME_NOT_FOUND),
        result, "GetKeepAliveProcessEnable failed");
    CHECK_TRUE_RETURN_RET((updateEnable == localEnable),
        ERR_OK, "no change to the KeepAlive process setting properties");

    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    CHECK_POINTER_AND_RETURN(appMgrClient, INNER_ERR);
    if (updateEnable) {
        bool isRunning = false;
        result = IN_PROCESS_CALL(appMgrClient->IsApplicationRunning(bundleName, isRunning));
        CHECK_RET_RETURN_RET(result, "IsApplicationRunning failed");
        CHECK_TRUE_RETURN_RET((!isRunning && !MainElementUtils::CheckStatusBarAbility(bundleInfo)),
            ERR_NO_STATUS_BAR_ABILITY, "app has no status bar");
        CHECK_TRUE_RETURN_RET((isRunning && !IsRunningAppInStatusBar(abilityMgr, bundleInfo)),
            ERR_NOT_ATTACHED_TO_STATUS_BAR, "app is not in status bar");
    }

    KeepAliveInfo info;
    info.bundleName = bundleName;
    info.userId = userId;
    result = isByEDM ? abilityKeepAliveService_->SetApplicationKeepAliveByEDM(info, updateEnable)
        : abilityKeepAliveService_->SetApplicationKeepAlive(info, updateEnable);
    CHECK_RET_RETURN_RET(result, "KeepAlive process attribute update failed");
    IN_PROCESS_CALL_WITHOUT_RET(appMgrClient->SetKeepAliveEnableState(bundleName, updateEnable, 0));
    UpdateKeepAliveProcessesStatus(bundleInfo, userId, localEnable, updateEnable);
    return ERR_OK;
}

bool KeepAliveProcessManager::IsRunningAppInStatusBar(std::shared_ptr<AbilityManagerService> abilityMgr,
    const AppExecFwk::BundleInfo &bundleInfo)
{
    CHECK_POINTER_AND_RETURN(abilityMgr, false);

    std::string mainElementName;
    if (!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle has no main uiability");
        return false;
    }
    uint32_t accessTokenId = 0;
    MainElementUtils::GetMainUIAbilityAccessTokenId(bundleInfo, mainElementName, accessTokenId);
    if (accessTokenId == 0) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "cannot get accessTokenId");
        return false;
    }
    return abilityMgr->IsInStatusBar(accessTokenId);
}

void KeepAliveProcessManager::UpdateKeepAliveProcessesStatus(
    const AppExecFwk::BundleInfo &bundleInfo, int32_t userId, bool localEnable, bool updateEnable)
{
    if (!updateEnable && localEnable) {
        // just update
        std::vector<AppExecFwk::BundleInfo> bundleInfos{ bundleInfo };
        KeepAliveUtils::NotifyDisableKeepAliveProcesses(bundleInfos, userId);
    }
}

void KeepAliveProcessManager::OnAppStateChanged(const AppInfo &info)
{
    if (info.state != AppState::BEGIN) {
        TAG_LOGD(AAFwkTag::KEEP_ALIVE, "Not a state of concern. state: %{public}d", info.state);
        return;
    }

    if (info.pid <= 0) {
        TAG_LOGD(AAFwkTag::KEEP_ALIVE, "The obtained application pid is incorrect. state: %{public}d", info.pid);
        return;
    }

    // user 0
    int32_t uid = 0;
    auto appScheduler = DelayedSingleton<AppScheduler>::GetInstance();
    if (appScheduler == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "app scheduler error");
        return;
    }
    std::string bundleName;
    appScheduler->GetBundleNameByPid(info.pid, bundleName, uid);
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "get bundle name by pid failed");
        return;
    }

    if (abilityKeepAliveService_ == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "abilityKeepAliveService_ null");
        return;
    }
    bool localEnable = false;
    auto result = abilityKeepAliveService_->GetKeepAliveProcessEnable(bundleName, -1, localEnable);
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "GetKeepAliveProcessEnable failed: %{public}d", result);
        return;
    }

    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "set keep alive enable state error");
        return;
    }
    IN_PROCESS_CALL_WITHOUT_RET(appMgrClient->SetKeepAliveEnableState(bundleName, localEnable, uid));
}

bool KeepAliveProcessManager::IsKeepAliveBundle(const std::string &bundleName, int32_t userId)
{
    CHECK_POINTER_AND_RETURN(abilityKeepAliveService_, false);
    bool keepAliveEnable = false;
    abilityKeepAliveService_->GetKeepAliveProcessEnable(bundleName, userId, keepAliveEnable);
    return keepAliveEnable;
}

bool KeepAliveProcessManager::GetKeepAliveBundleInfosForUser(std::vector<AppExecFwk::BundleInfo> &bundleInfos,
    int32_t userId)
{
    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    CHECK_POINTER_AND_RETURN(bundleMgrHelper, false);

    CHECK_POINTER_AND_RETURN(abilityKeepAliveService_, false);

    std::vector<KeepAliveInfo> infoList;
    auto ret = abilityKeepAliveService_->GetKeepAliveApplications(userId, infoList);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "failed get keep_alive bundle info: %{public}d", ret);
        return false;
    }
    for (const auto &info: infoList) {
        AppExecFwk::BundleInfo bundleInfo;
        if (!IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfo(info.bundleName,
            AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, userId))) {
            TAG_LOGW(AAFwkTag::KEEP_ALIVE, "failed get bundle info: %{public}s", info.bundleName.c_str());
            continue;
        }
        bundleInfos.push_back(bundleInfo);
    }

    return !bundleInfos.empty();
}

void KeepAliveProcessManager::StartFailedKeepAliveAbilities()
{
    unlockedAfterBoot_ = true;
    std::list<KeepAliveAbilityInfo> tmpList;
    {
        std::lock_guard lock(failedKeepAliveAbilityInfoMutex_);
        if (failedKeepAliveAbilityInfos_.empty()) {
            TAG_LOGI(AAFwkTag::KEEP_ALIVE, "no failed abilities");
            return;
        }
        tmpList = std::move(failedKeepAliveAbilityInfos_);
    }
    for (const auto &item: tmpList) {
        (void)StartAbility(item.bundleName, item.moduleName, item.abilityName, item.userId);
    }
}

void KeepAliveProcessManager::AddFailedKeepAliveAbility(const std::string &bundleName,
    const std::string &moduleName, const std::string &abilityName, int32_t userId)
{
    TAG_LOGI(AAFwkTag::KEEP_ALIVE, "failed bundleName: %{public}s, mainElement: %{public}s",
        bundleName.c_str(), abilityName.c_str());
    if (unlockedAfterBoot_) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "already unlocked");
        return;
    }

    std::lock_guard lock(failedKeepAliveAbilityInfoMutex_);
    failedKeepAliveAbilityInfos_.push_back(KeepAliveAbilityInfo {
        .bundleName = bundleName,
        .moduleName = moduleName,
        .abilityName = abilityName,
        .userId = userId,
    });
}

int32_t KeepAliveProcessManager::QueryKeepAliveApplications(int32_t appType, int32_t userId,
    std::vector<KeepAliveInfo> &infoList, bool isByEDM)
{
    CHECK_POINTER_AND_RETURN(abilityKeepAliveService_, INNER_ERR);
    if (isByEDM) {
        return abilityKeepAliveService_->QueryKeepAliveApplicationsByEDM(userId, appType, infoList);
    }
    return abilityKeepAliveService_->QueryKeepAliveApplications(userId, appType, infoList);
}
}  // namespace AAFwk
}  // namespace OHOS
