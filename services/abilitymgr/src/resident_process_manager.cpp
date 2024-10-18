/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "resident_process_manager.h"

#include "ability_manager_service.h"
#include "ability_resident_process_rdb.h"
#include "ability_util.h"
#include "ffrt.h"

namespace OHOS {
namespace AAFwk {
namespace {
bool IsMainElementTypeOk(const AppExecFwk::HapModuleInfo &hapModuleInfo, const std::string &mainElement,
    int32_t userId)
{
    if (userId == 0) {
        for (const auto &abilityInfo: hapModuleInfo.abilityInfos) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "compare ability: %{public}s", abilityInfo.name.c_str());
            if (abilityInfo.name == mainElement) {
                return abilityInfo.type != AppExecFwk::AbilityType::PAGE;
            }
        }
        return true;
    } else {
        for (const auto &extensionInfo: hapModuleInfo.extensionInfos) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "compare extension: %{public}s", extensionInfo.name.c_str());
            if (extensionInfo.name == mainElement) {
                return extensionInfo.type == AppExecFwk::ExtensionAbilityType::SERVICE;
            }
        }
        return false;
    }
}
}

ResidentAbilityInfoGuard::ResidentAbilityInfoGuard(const std::string &bundleName,
    const std::string &abilityName, int32_t userId)
{
    residentId_ = DelayedSingleton<ResidentProcessManager>::GetInstance()->PutResidentAbility(bundleName,
        abilityName, userId);
}

ResidentAbilityInfoGuard::~ResidentAbilityInfoGuard()
{
    if (residentId_ != -1) {
        DelayedSingleton<ResidentProcessManager>::GetInstance()->RemoveResidentAbility(residentId_);
    }
}

void ResidentAbilityInfoGuard::SetResidentAbilityInfo(const std::string &bundleName,
    const std::string &abilityName, int32_t userId)
{
    if (residentId_ != -1) {
        return;
    }
    residentId_ = DelayedSingleton<ResidentProcessManager>::GetInstance()->PutResidentAbility(bundleName,
        abilityName, userId);
}

ResidentProcessManager::ResidentProcessManager()
{}

ResidentProcessManager::~ResidentProcessManager()
{}

void ResidentProcessManager::Init()
{
    auto &amsRdb = AmsResidentProcessRdb::GetInstance();
    amsRdb.Init();
}

void ResidentProcessManager::StartResidentProcess(const std::vector<AppExecFwk::BundleInfo> &bundleInfos)
{
    DelayedSingleton<AppScheduler>::GetInstance()->StartupResidentProcess(bundleInfos);
}

void ResidentProcessManager::StartResidentProcessWithMainElement(std::vector<AppExecFwk::BundleInfo> &bundleInfos,
    int32_t userId)
{
    std::set<uint32_t> needEraseIndexSet;

    for (size_t i = 0; i < bundleInfos.size(); i++) {
        if (userId != 0 && !AmsConfigurationParameter::GetInstance().InResidentWhiteList(bundleInfos[i].name)) {
            needEraseIndexSet.insert(i);
            continue;
        }
        std::string processName = bundleInfos[i].applicationInfo.process;
        bool keepAliveEnable = bundleInfos[i].isKeepAlive;
        // Check startup permissions
        AmsResidentProcessRdb::GetInstance().GetResidentProcessEnable(bundleInfos[i].name, keepAliveEnable);
        if (!keepAliveEnable || processName.empty()) {
            needEraseIndexSet.insert(i);
            continue;
        }
        for (auto hapModuleInfo : bundleInfos[i].hapModuleInfos) {
            std::string mainElement;
            if (!CheckMainElement(hapModuleInfo, processName, mainElement, needEraseIndexSet, i, userId)) {
                continue;
            }

            needEraseIndexSet.insert(i);
            // startAbility
            Want want;
            want.SetElementName(hapModuleInfo.bundleName, mainElement);
            ResidentAbilityInfoGuard residentAbilityInfoGuard(hapModuleInfo.bundleName, mainElement, userId);
            TAG_LOGI(AAFwkTag::ABILITYMGR, "Start resident ability, bundleName: %{public}s, mainElement: %{public}s",
                hapModuleInfo.bundleName.c_str(), mainElement.c_str());
            DelayedSingleton<AbilityManagerService>::GetInstance()->StartAbility(want, userId,
                DEFAULT_INVAL_VALUE);
        }
    }

    // delete item which process has been started.
    for (auto iter = needEraseIndexSet.rbegin(); iter != needEraseIndexSet.rend(); iter++) {
        bundleInfos.erase(bundleInfos.begin() + *iter);
    }
}

bool ResidentProcessManager::CheckMainElement(const AppExecFwk::HapModuleInfo &hapModuleInfo,
    const std::string &processName, std::string &mainElement,
    std::set<uint32_t> &needEraseIndexSet, size_t bundleInfoIndex, int32_t userId)
{
    if (!hapModuleInfo.isModuleJson) {
        // old application model
        mainElement = hapModuleInfo.mainAbility;
        if (mainElement.empty()) {
            return false;
        }

        // old application model, use ability 'process'
        bool isAbilityKeepAlive = false;
        for (auto abilityInfo : hapModuleInfo.abilityInfos) {
            if (abilityInfo.process != processName || abilityInfo.name != mainElement) {
                continue;
            }
            isAbilityKeepAlive = true;
        }
        if (!isAbilityKeepAlive) {
            return false;
        }

        std::string uriStr;
        bool getDataAbilityUri = DelayedSingleton<AbilityManagerService>::GetInstance()->GetDataAbilityUri(
            hapModuleInfo.abilityInfos, mainElement, uriStr);
        if (getDataAbilityUri) {
            // dataability, need use AcquireDataAbility
            TAG_LOGI(AAFwkTag::ABILITYMGR, "Start resident dataability, mainElement: %{public}s, uri: %{public}s",
                mainElement.c_str(), uriStr.c_str());
            Uri uri(uriStr);
            DelayedSingleton<AbilityManagerService>::GetInstance()->AcquireDataAbility(uri, true, nullptr);
            needEraseIndexSet.insert(bundleInfoIndex);
            return false;
        }
    } else {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "new mode: %{public}s", hapModuleInfo.bundleName.c_str());
        // new application model
        mainElement = hapModuleInfo.mainElementName;
        if (mainElement.empty()) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "mainElement empty");
            return false;
        }

        // new application model, user model 'process'
        if (hapModuleInfo.process != processName) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "processName err: %{public}s", processName.c_str());
            return false;
        }
    }
    return IsMainElementTypeOk(hapModuleInfo, mainElement, userId);
}

int32_t ResidentProcessManager::SetResidentProcessEnabled(
    const std::string &bundleName, const std::string &callerName, bool updateEnable)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Called");
    if (bundleName.empty() || callerName.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Input parameter error");
        return INVALID_PARAMETERS_ERR;
    }
    auto &rdb = AmsResidentProcessRdb::GetInstance();
    auto rdbResult = rdb.VerifyConfigurationPermissions(bundleName, callerName);
    if (rdbResult != Rdb_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Failed to obtain permissions. result: %{public}d", rdbResult);
        return ERR_NO_RESIDENT_PERMISSION;
    }

    bool localEnable = false;
    rdbResult = rdb.GetResidentProcessEnable(bundleName, localEnable);
    if (rdbResult != Rdb_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Failed to obtain resident process properties. result: %{public}d", rdbResult);
        return INNER_ERR;
    }

    if (updateEnable == localEnable) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "The setting properties of the resident process have not changed");
        return ERR_OK;
    }

    rdbResult = rdb.UpdateResidentProcessEnable(bundleName, updateEnable);
    if (rdbResult != Rdb_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Resident process attribute update failed");
        return INNER_ERR;
    }

    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    if (appMgrClient != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Set keep alive enable state.");
        IN_PROCESS_CALL_WITHOUT_RET(appMgrClient->SetKeepAliveEnableState(bundleName, updateEnable, 0));
    }

    ffrt::submit([self = shared_from_this(), bundleName, localEnable, updateEnable]() {
        self->UpdateResidentProcessesStatus(bundleName, localEnable, updateEnable);
    });
    return ERR_OK;
}

void ResidentProcessManager::UpdateResidentProcessesStatus(
    const std::string &bundleName, bool localEnable, bool updateEnable)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Bundle name is empty!");
        return;
    }

    auto bms = AbilityUtil::GetBundleManagerHelper();
    if (bms == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Failed to obtain bms handle!");
        return;
    }

    AppExecFwk::BundleInfo bundleInfo;
    auto currentUser = DelayedSingleton<AbilityManagerService>::GetInstance()->GetUserId();
    std::set<int32_t> users{0, currentUser};

    for (const auto &userId: users) {
        if (!IN_PROCESS_CALL(bms->GetBundleInfo(
            bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId))) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "get bundle info failed");
            break;
        }

        // need start
        if (updateEnable && !localEnable) {
            std::vector<AppExecFwk::BundleInfo> bundleInfos{ bundleInfo };
            StartResidentProcessWithMainElement(bundleInfos, userId);
            if (!bundleInfos.empty()) {
                StartResidentProcess(bundleInfos);
            }
        }
    }
}

void ResidentProcessManager::OnAppStateChanged(const AppInfo &info)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Called");
    if (info.state != AppState::BEGIN) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Not a state of concern. state: %{public}d", info.state);
        return;
    }

    if (info.pid <= 0) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "The obtained application pid is incorrect. state: %{public}d", info.pid);
        return;
    }

    std::string bundleName;
    // user 0
    int32_t uid = 0;
    auto appScheduler = DelayedSingleton<AppScheduler>::GetInstance();
    if (appScheduler == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "App scheduler error.");
        return;
    }
    appScheduler->GetBundleNameByPid(info.pid, bundleName, uid);
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Get bundle name by pid failed.");
        return;
    }

    bool localEnable = false;
    auto rdbResult = AmsResidentProcessRdb::GetInstance().GetResidentProcessEnable(bundleName, localEnable);
    if (rdbResult != Rdb_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Failed to obtain resident process properties. result: %{public}d", rdbResult);
        return;
    }

    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Set keep alive enable state error.");
        return;
    }
    IN_PROCESS_CALL_WITHOUT_RET(appMgrClient->SetKeepAliveEnableState(bundleName, localEnable, 0));
}

int32_t ResidentProcessManager::PutResidentAbility(const std::string &bundleName,
    const std::string &abilityName, int32_t userId)
{
    std::lock_guard lock(residentAbilityInfoMutex_);
    auto residentId = residentId_++;
    residentAbilityInfos_.push_back(ResidentAbilityInfo {
        .bundleName = bundleName,
        .abilityName = abilityName,
        .userId = userId,
        .residentId = residentId
    });
    return residentId;
}

bool ResidentProcessManager::IsResidentAbility(const std::string &bundleName,
    const std::string &abilityName, int32_t userId)
{
    std::lock_guard lock(residentAbilityInfoMutex_);
    for (const auto &item: residentAbilityInfos_) {
        if (item.bundleName == bundleName && item.abilityName == abilityName && item.userId == userId) {
            return true;
        }
    }
    return false;
}

void ResidentProcessManager::RemoveResidentAbility(int32_t residentId)
{
    std::lock_guard lock(residentAbilityInfoMutex_);
    for (auto it = residentAbilityInfos_.begin(); it != residentAbilityInfos_.end(); ++it) {
        if (it->residentId == residentId) {
            residentAbilityInfos_.erase(it);
            return;
        }
    }
}

bool ResidentProcessManager::GetResidentBundleInfosForUser(std::vector<AppExecFwk::BundleInfo> &bundleInfos,
    int32_t userId)
{
    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    CHECK_POINTER_AND_RETURN(bundleMgrHelper, false);

    const auto &residentWhiteList = AmsConfigurationParameter::GetInstance().GetResidentWhiteList();
    if (userId == 0 || residentWhiteList.empty()) {
        return IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfos(OHOS::AppExecFwk::GET_BUNDLE_DEFAULT,
            bundleInfos, userId));
    }

    for (const auto &bundleName: residentWhiteList) {
        AppExecFwk::BundleInfo bundleInfo;
        if (!IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfo(bundleName,
            AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, userId))) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "failed get bundle info: %{public}s", bundleName.c_str());
            continue;
        }
        bundleInfos.push_back(bundleInfo);
    }

    return !bundleInfos.empty();
}
}  // namespace AAFwk
}  // namespace OHOS
