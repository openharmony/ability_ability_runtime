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

#include <utility>

#include "ability_util.h"
#include "ffrt.h"
#include "keep_alive_utils.h"
#include "main_element_utils.h"
#include "parameters.h"
#include "permission_constants.h"
#include "process_options.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr char PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED[] = "const.product.enterprisefeature.setting.enabled";
constexpr char FOUNDATION_PROCESS_NAME[] = "foundation";
constexpr int MAX_RETRY_TIMES = 3;
constexpr int RETRY_INTERVAL_MICRO_SECONDS = 200000; // 200ms
constexpr int CREATE_STATUS_BAR_TIMEOUT_MICRO_SECONDS = 5000000; // 5s
} // namespace

void CheckStatusBarTask::Cancel()
{
    std::lock_guard<ffrt::mutex> lock(cancelMutex_);
    task_ = nullptr;
}

void CheckStatusBarTask::Run()
{
    std::lock_guard<ffrt::mutex> lock(cancelMutex_);
    if (task_ == nullptr) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "task is canceled");
        return;
    }

    TAG_LOGI(AAFwkTag::KEEP_ALIVE, "run check task");
    task_();
}

KeepAliveProcessManager &KeepAliveProcessManager::GetInstance()
{
    static KeepAliveProcessManager instance;
    return instance;
}

KeepAliveProcessManager::KeepAliveProcessManager() {}

KeepAliveProcessManager::~KeepAliveProcessManager() {}

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
    if (!IsKeepAliveBundle(bundleInfo.name, userId)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle is not set keep-alive");
        return;
    }

    std::string mainElementName;
    if (!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle has no main uiability");
        return;
    }
    KeepAliveAbilityInfo info = {
        .bundleName = bundleInfo.name,
        .moduleName = bundleInfo.entryModuleName,
        .abilityName = mainElementName,
        .userId = userId,
        .appCloneIndex = bundleInfo.appIndex,
        .uid = bundleInfo.uid,
    };
    auto ret = StartKeepAliveMainAbility(info);
    if (ret == ERR_OK) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "start ok");
        AfterStartKeepAliveApp(bundleInfo.name, bundleInfo.applicationInfo.accessTokenId,
            bundleInfo.uid, userId);
        return;
    }

    TAG_LOGE(AAFwkTag::KEEP_ALIVE, "StartKeepAliveMainAbility failed:%{public}d, retry", ret);
    ffrt::submit([bundleName = bundleInfo.name, accessTokenId = bundleInfo.applicationInfo.accessTokenId,
        uid = bundleInfo.uid, userId, info, ret]() mutable {
        for (int tried = 0; tried < MAX_RETRY_TIMES && ret != ERR_OK; tried++) {
            usleep(RETRY_INTERVAL_MICRO_SECONDS);
            TAG_LOGI(AAFwkTag::KEEP_ALIVE, "retry attempt:%{public}d", tried + 1);
            ret = KeepAliveProcessManager::GetInstance().StartKeepAliveMainAbility(info);
            TAG_LOGI(AAFwkTag::KEEP_ALIVE, "retry result:%{public}d", ret);
        }
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "reach max retry, failed:%{public}d, unsetting keep-alive", ret);
            KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId, false, true, true);
            return;
        }
        KeepAliveProcessManager::GetInstance().AfterStartKeepAliveApp(bundleName, accessTokenId, uid, userId);
    });
}

int32_t KeepAliveProcessManager::StartKeepAliveMainAbility(const KeepAliveAbilityInfo &info)
{
    Want want;
    want.SetElementName(info.bundleName, info.abilityName);
    want.SetParam(Want::PARAM_APP_CLONE_INDEX_KEY, info.appCloneIndex);
    TAG_LOGI(AAFwkTag::KEEP_ALIVE, "call, bundleName: %{public}s, moduleName: %{public}s, mainElement: %{public}s"
        " appCloneIndex: %{public}d", info.bundleName.c_str(), info.moduleName.c_str(), info.abilityName.c_str(),
        info.appCloneIndex);
    StartOptions options;
    options.processOptions = std::make_shared<ProcessOptions>();
    options.processOptions->isRestartKeepAlive = true;
    options.processOptions->startupVisibility =
        DelayedSingleton<AbilityManagerService>::GetInstance()->IsSupportStatusBar(info.uid) ?
        StartupVisibility::STARTUP_HIDE : StartupVisibility::STARTUP_SHOW;
    auto ret = IN_PROCESS_CALL(DelayedSingleton<AbilityManagerService>::GetInstance()->StartAbility(want,
        options, nullptr, info.userId, DEFAULT_INVAL_VALUE));
    MainElementUtils::UpdateMainElement(info.bundleName, info.moduleName, info.abilityName, true, info.userId);
    return ret;
}

void KeepAliveProcessManager::AfterStartKeepAliveApp(const std::string &bundleName,
    uint32_t accessTokenId, int32_t uid, int32_t userId)
{
    // not support statusbar and don't need check after 5s
    if (DelayedSingleton<AbilityManagerService>::GetInstance()->IsSupportStatusBar(uid)) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "not support statusBar, don't need check when keep alive");
        return;
    }

    auto task = [bundleName, accessTokenId, uid, userId]() {
        bool isStatusBarCreated =
            DelayedSingleton<AbilityManagerService>::GetInstance()->IsInStatusBar(accessTokenId, uid);
        (void)KeepAliveProcessManager::GetInstance().RemoveCheckStatusBarTask(uid, false);
        if (isStatusBarCreated) {
            TAG_LOGI(AAFwkTag::KEEP_ALIVE, "status bar is created");
            return;
        }
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "timeout, status bar not created, unsetting keep-alive");
        KeepAliveProcessManager::GetInstance().SetApplicationKeepAlive(bundleName, userId, false, true, true);
        (void)DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplication(bundleName);
    };

    std::lock_guard<ffrt::mutex> lock(checkStatusBarTasksMutex_);
    auto iter = std::find_if(checkStatusBarTasks_.begin(), checkStatusBarTasks_.end(),
        [uid](const std::shared_ptr<CheckStatusBarTask> &curTask) {
        return curTask != nullptr && curTask->GetUid() == uid;
    });
    if (iter != checkStatusBarTasks_.end()) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "exists same task, canceling");
        if (*iter != nullptr) {
            (*iter)->Cancel();
        }
        checkStatusBarTasks_.erase(iter);
    }
    auto checkStatusBarTask = std::make_shared<CheckStatusBarTask>(uid, std::move(task));
    checkStatusBarTasks_.push_back(checkStatusBarTask);
    ffrt::task_attr attr;
    attr.delay(CREATE_STATUS_BAR_TIMEOUT_MICRO_SECONDS);
    ffrt::submit([checkStatusBarTask]() {
        if (checkStatusBarTask != nullptr) {
            checkStatusBarTask->Run();
        }
        }, attr);
}

void KeepAliveProcessManager::RemoveCheckStatusBarTask(int32_t uid, bool shouldCancel)
{
    std::lock_guard<ffrt::mutex> lock(checkStatusBarTasksMutex_);
    auto iter = std::find_if(checkStatusBarTasks_.begin(), checkStatusBarTasks_.end(),
        [uid](const std::shared_ptr<CheckStatusBarTask> &curTask) {
        return curTask != nullptr && curTask->GetUid() == uid;
    });
    if (iter == checkStatusBarTasks_.end()) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "not exist");
        return;
    }
    if (*iter != nullptr && shouldCancel) {
        (*iter)->Cancel();
    }
    checkStatusBarTasks_.erase(iter);
}

int32_t KeepAliveProcessManager::SetApplicationKeepAlive(const std::string &bundleName,
    int32_t userId, bool updateEnable, bool isByEDM, bool isInner)
{
    auto result = isByEDM ? CheckPermissionForEDM() : CheckPermission();
    CHECK_RET_RETURN_RET(result, "permission denied");

    CHECK_TRUE_RETURN_RET(bundleName.empty(), INVALID_PARAMETERS_ERR, "input parameter error");

    auto bms = AbilityUtil::GetBundleManagerHelper();
    CHECK_POINTER_AND_RETURN(bms, INNER_ERR);

    userId = userId < 0 ? DelayedSingleton<AbilityManagerService>::GetInstance()->GetUserId() : userId;
    AppExecFwk::BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(bms->GetBundleInfo(
        bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId))) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "get bundle info failed");
        return ERR_TARGET_BUNDLE_NOT_EXIST;
    }

    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    CHECK_POINTER_AND_RETURN(appMgrClient, INNER_ERR);

    bool localEnable = IsKeepAliveBundle(bundleName, userId);
    if (updateEnable) {
        std::string mainElementName;
        CHECK_TRUE_RETURN_RET(!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName),
            ERR_NO_MAIN_ABILITY, "bundle has no main uiability");
        if (DelayedSingleton<AbilityManagerService>::GetInstance()->IsSupportStatusBar(bundleInfo.uid)) {
            CHECK_TRUE_RETURN_RET(!MainElementUtils::CheckStatusBarAbility(bundleInfo),
                ERR_NO_STATUS_BAR_ABILITY, "app has no status bar");
            bool isRunning = false;
            result = IN_PROCESS_CALL(appMgrClient->IsAppRunningByBundleNameAndUserId(bundleName, userId, isRunning));
            CHECK_RET_RETURN_RET(result, "IsAppRunning failed");
            CHECK_TRUE_RETURN_RET((isRunning && !IsRunningAppInStatusBar(bundleInfo)),
                ERR_NOT_ATTACHED_TO_STATUS_BAR, "app is not attached to status bar");
        }
    }

    KeepAliveInfo info;
    info.bundleName = bundleName;
    info.userId = userId;
    info.appType = bundleInfo.applicationInfo.isSystemApp ? KeepAliveAppType::SYSTEM : KeepAliveAppType::THIRD_PARTY;
    info.setter = isByEDM ? KeepAliveSetter::SYSTEM : KeepAliveSetter::USER;
    result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, updateEnable);
    CHECK_RET_RETURN_RET(result, "set keep-alive failed");
    IN_PROCESS_CALL_WITHOUT_RET(appMgrClient->SetKeepAliveDkv(bundleName, updateEnable, 0));
    if (!updateEnable && localEnable) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "unsetting keep-alive");
        if (!isInner) {
            RemoveCheckStatusBarTask(bundleInfo.uid, true);
        }
        std::vector<AppExecFwk::BundleInfo> bundleInfos{ bundleInfo };
        KeepAliveUtils::NotifyDisableKeepAliveProcesses(bundleInfos, userId);
    }
    return ERR_OK;
}

bool KeepAliveProcessManager::IsRunningAppInStatusBar(const AppExecFwk::BundleInfo &bundleInfo)
{
    std::string mainElementName;
    if (!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle has no main uiability");
        return false;
    }
    return DelayedSingleton<AbilityManagerService>::GetInstance()->IsInStatusBar(
        bundleInfo.applicationInfo.accessTokenId, bundleInfo.uid);
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

    bool localEnable = IsKeepAliveBundle(bundleName, -1);
    if (!localEnable) {
        return;
    }

    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "appMgrClient is null");
        return;
    }
    IN_PROCESS_CALL_WITHOUT_RET(appMgrClient->SetKeepAliveDkv(bundleName, localEnable, uid));
}

bool KeepAliveProcessManager::IsKeepAliveBundle(const std::string &bundleName, int32_t userId)
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "not supported");
        return false;
    }
    return AbilityKeepAliveService::GetInstance().IsKeepAliveApp(bundleName, userId);
}

bool KeepAliveProcessManager::GetKeepAliveBundleInfosForUser(std::vector<AppExecFwk::BundleInfo> &bundleInfos,
    int32_t userId)
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGW(AAFwkTag::KEEP_ALIVE, "not supported");
        return false;
    }
    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    CHECK_POINTER_AND_RETURN(bundleMgrHelper, false);

    std::vector<KeepAliveInfo> infoList;
    auto ret = AbilityKeepAliveService::GetInstance().GetKeepAliveApplications(userId, infoList);
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

int32_t KeepAliveProcessManager::QueryKeepAliveApplications(int32_t appType, int32_t userId,
    std::vector<KeepAliveInfo> &infoList, bool isByEDM)
{
    auto result = isByEDM ? CheckPermissionForEDM() : CheckPermission();
    CHECK_RET_RETURN_RET(result, "permission denied");
    return AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(userId, appType, infoList);
}

int32_t KeepAliveProcessManager::CheckPermission()
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "not supported");
        return ERR_CAPABILITY_NOT_SUPPORT;
    }

    if (!PermissionVerification::GetInstance()->JudgeCallerIsAllowedToUseSystemAPI()) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "not use system-api");
        return ERR_NOT_SYSTEM_APP;
    }

    if (!PermissionVerification::GetInstance()->VerifyCallingPermission(
        PermissionConstants::PERMISSION_MANAGE_APP_KEEP_ALIVE)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "verify PERMISSION_MANAGE_APP_KEEP_ALIVE fail");
        return CHECK_PERMISSION_FAILED;
    }

    return ERR_OK;
}

int32_t KeepAliveProcessManager::CheckPermissionForEDM()
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "not supported");
        return ERR_CAPABILITY_NOT_SUPPORT;
    }
    if (PermissionVerification::GetInstance()->CheckSpecificSystemAbilityAccessPermission(FOUNDATION_PROCESS_NAME)
        || (PermissionVerification::GetInstance()->IsSACall()
        && PermissionVerification::GetInstance()->VerifyCallingPermission(
            PermissionConstants::PERMISSION_MANAGE_APP_KEEP_ALIVE_INTERNAL))) {
        return ERR_OK;
    }
    TAG_LOGE(AAFwkTag::KEEP_ALIVE, "verify PERMISSION_MANAGE_APP_KEEP_ALIVE_INTERNAL fail");
    return CHECK_PERMISSION_FAILED;
}
}  // namespace AAFwk
}  // namespace OHOS
