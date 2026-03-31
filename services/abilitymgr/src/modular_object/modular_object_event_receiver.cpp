/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "modular_object_event_receiver.h"

#include "bundle_mgr_helper.h"
#include "common_event_support.h"
#include "ffrt.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "modular_object_rdb_storage_mgr.h"
#include "os_account_manager_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const std::string KEY_USER_ID = "userId";
const std::string KEY_APP_INDEX = "appIndex";
const std::string IS_DISABLED = "isDisabled";
const std::string PROCESS_MODE = "processMode";
const std::string THREAD_MODE = "threadMode";
const std::string LAUNCH_MODE = "launchMode";
} // namespace

ModularObjectEventReceiver::ModularObjectEventReceiver(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
    TAG_LOGD(AAFwkTag::EXT, "modular object event receiver created");
}

void ModularObjectEventReceiver::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const std::string action = data.GetWant().GetAction();
    TAG_LOGI(AAFwkTag::EXT, "received event action: %{public}s", action.c_str());

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        HandleEventUserSwitched(data);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        HandleBundleInstall(data);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        HandleBundleRemoved(data);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        HandleBundleChanged(data);
    } else {
        TAG_LOGW(AAFwkTag::EXT, "invalid action");
    }
}

void ModularObjectEventReceiver::LoadModularObjectExtensionInfos()
{
    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "null bundleMgrHelper");
        return;
    }

    int32_t userId = AppExecFwk::OsAccountManagerWrapper::GetCurrentActiveAccountId();
    TAG_LOGD(AAFwkTag::EXT, "init modular object, userId: %{public}d", userId);

    std::vector<AppExecFwk::BundleInfo> bundleInfos {};
    if (!IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfos(AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO,
        bundleInfos, userId)) != ERR_OK) {
        TAG_LOGE(AAFwkTag::EXT, "get bundle infos failed");
        return;
    }
    TAG_LOGD(AAFwkTag::EXT, "bundleInfos size: %{public}zu", bundleInfos.size());
    std::vector<AAFwk::ModularObjectExtensionInfo> infos;
    for (const auto &bundleInfo : bundleInfos) {
        GetModularObjectExtensionInfos(bundleInfo, infos);
        std::string key = GenerateModularObjectKey(userId, bundleInfo.name, bundleInfo.appIndex);
        DelayedSingleton<ModularObjectExtensionRdbStorageMgr>::GetInstance()->InsertData(key, infos);
        infos.clear();
    }
}

void ModularObjectEventReceiver::HandleEventUserSwitched(const EventFwk::CommonEventData &data)
{
    auto task = [self = shared_from_this()]() { self->LoadModularObjectExtensionInfos(); };
    ffrt::submit(task);
}

void ModularObjectEventReceiver::HandleBundleInstall(const EventFwk::CommonEventData &data)
{
    const AAFwk::Want& want = data.GetWant();
    std::string bundleName = want.GetElement().GetBundleName();
    TAG_LOGI(AAFwkTag::EXT, "handle common event package add, bundleName: %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::EXT, "bundle name is empty");
        return;
    }
    int32_t userId = want.GetIntParam(KEY_USER_ID, -1);
    if (userId < 0) {
        TAG_LOGE(AAFwkTag::EXT, "invalid userId: %{public}d", userId);
        return;
    }
    int32_t appIndex = data.GetWant().GetIntParam(KEY_APP_INDEX, 0);

    ffrt::submit([self = shared_from_this(), bundleName, userId, appIndex]() {
        self->InsertModularObjectExtensionInfo(bundleName, userId, appIndex);
    });
}

void ModularObjectEventReceiver::HandleBundleRemoved(const EventFwk::CommonEventData &data)
{
    const AAFwk::Want& want = data.GetWant();
    std::string bundleName = want.GetElement().GetBundleName();
    TAG_LOGI(AAFwkTag::EXT, "handle common event package remove, bundleName: %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::EXT, "bundle name is empty");
        return;
    }
    int32_t userId = want.GetIntParam(KEY_USER_ID, -1);
    if (userId < 0) {
        TAG_LOGE(AAFwkTag::EXT, "invalid userId: %{public}d", userId);
        return;
    }
    int32_t appIndex = data.GetWant().GetIntParam(KEY_APP_INDEX, 0);

    ffrt::submit([self = shared_from_this(), bundleName, userId, appIndex]() {
        self->RemoveModularObjectExtensionInfo(bundleName, userId, appIndex);
    });
}

void ModularObjectEventReceiver::HandleBundleChanged(const EventFwk::CommonEventData &data)
{
    const AAFwk::Want& want = data.GetWant();
    std::string bundleName = want.GetElement().GetBundleName();
    TAG_LOGI(AAFwkTag::EXT, "handle common event package changed, bundleName: %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::EXT, "bundle name is empty");
        return;
    }
    int32_t userId = want.GetIntParam(KEY_USER_ID, -1);
    if (userId < 0) {
        TAG_LOGE(AAFwkTag::EXT, "invalid userId: %{public}d", userId);
        return;
    }
    int32_t appIndex = data.GetWant().GetIntParam(KEY_APP_INDEX, 0);

    ffrt::submit([self = shared_from_this(), bundleName, userId, appIndex]() {
        self->UpdateModularObjectExtensionInfos(bundleName, userId, appIndex);
    });
}

void ModularObjectEventReceiver::InsertModularObjectExtensionInfo(
    const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "bundleMgrHelper is null");
        return;
    }

    AppExecFwk::BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfo(bundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO, bundleInfo, userId))) {
        TAG_LOGW(AAFwkTag::EXT, "get bundle info failed, bundleName: %{public}s", bundleName.c_str());
        return;
    }

    std::vector<AAFwk::ModularObjectExtensionInfo> infos;
    GetModularObjectExtensionInfos(bundleInfo, infos);
    if (infos.empty()) {
        TAG_LOGD(AAFwkTag::EXT, "not include modular extension, bundleName: %{public}s", bundleName.c_str());
        return;
    }
    std::string key = GenerateModularObjectKey(userId, bundleName, appIndex);
    DelayedSingleton<ModularObjectExtensionRdbStorageMgr>::GetInstance()->InsertData(key, infos);
}

void ModularObjectEventReceiver::UpdateModularObjectExtensionInfos(const std::string &bundleName, int32_t userId,
    int32_t appIndex)
{
    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "bundleMgrHelper is null");
        return;
    }

    AppExecFwk::BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfo(bundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO, bundleInfo, userId))) {
        TAG_LOGW(AAFwkTag::EXT, "get bundle info failed, bundleName: %{public}s", bundleName.c_str());
        return;
    }

    std::vector<AAFwk::ModularObjectExtensionInfo> infos;
    GetModularObjectExtensionInfos(bundleInfo, infos);
    std::string key = GenerateModularObjectKey(userId, bundleName, appIndex);
    if (infos.empty()) {
        DelayedSingleton<ModularObjectExtensionRdbStorageMgr>::GetInstance()->DeleteData(key);
        return;
    }
    DelayedSingleton<ModularObjectExtensionRdbStorageMgr>::GetInstance()->UpdateData(key, infos);
}

void ModularObjectEventReceiver::RemoveModularObjectExtensionInfo(
    const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    std::string key = GenerateModularObjectKey(userId, bundleName, appIndex);
    DelayedSingleton<ModularObjectExtensionRdbStorageMgr>::GetInstance()->DeleteData(key);
}

void ModularObjectEventReceiver::ProcessMetadata(const std::vector<AppExecFwk::Metadata> &metadata,
    AAFwk::ModularObjectExtensionInfo &info)
{
    for (const auto &metadataItem : metadata) {
        if (metadataItem.name == IS_DISABLED) {
            info.isDisabled = metadataItem.value == "true";
        } else if (metadataItem.name == LAUNCH_MODE) {
            if (metadataItem.value == "IN_PROCESS") {
                info.launchMode = AAFwk::MoeLaunchMode::IN_PROCESS;
            } else if (metadataItem.value == "CROSS_PROCESS") {
                info.launchMode = AAFwk::MoeLaunchMode::CROSS_PROCESS;
            }
        } else if (metadataItem.name == THREAD_MODE) {
            if (metadataItem.value == "BUNDLE") {
                info.threadMode = AAFwk::MoeThreadMode::BUNDLE;
            } else if (metadataItem.value == "TYPE") {
                info.threadMode = AAFwk::MoeThreadMode::TYPE;
            } else if (metadataItem.value == "INSTANCE") {
                info.threadMode = AAFwk::MoeThreadMode::INSTANCE;
            }
        } else if (metadataItem.name == PROCESS_MODE) {
            if (metadataItem.value == "BUNDLE") {
                info.processMode = AAFwk::MoeProcessMode::BUNDLE;
            } else if (metadataItem.value == "TYPE") {
                info.processMode = AAFwk::MoeProcessMode::TYPE;
            } else if (metadataItem.value == "INSTANCE") {
                info.processMode = AAFwk::MoeProcessMode::INSTANCE;
            }
        }
    }
}

void ModularObjectEventReceiver::GetModularObjectExtensionInfos(const AppExecFwk::BundleInfo &bundleInfo,
    std::vector<AAFwk::ModularObjectExtensionInfo> &infos)
{
    for (const auto &extensionInfo : bundleInfo.extensionInfos) {
        if (extensionInfo.type != AppExecFwk::ExtensionAbilityType::MODULAR_OBJECT) {
            continue;
        }
        AAFwk::ModularObjectExtensionInfo info;
        info.bundleName = extensionInfo.bundleName;
        info.moduleName = extensionInfo.moduleName;
        info.abilityName = extensionInfo.name;
        info.appIndex = extensionInfo.appIndex;
        ProcessMetadata(extensionInfo.metadata, info);
        infos.emplace_back(info);
    }
}

std::string ModularObjectEventReceiver::GenerateModularObjectKey(int32_t userId, const std::string &bundleName,
    int32_t appIndex)
{
    return std::to_string(userId) + "_" + bundleName + "_" + std::to_string(appIndex);
}
} // namespace AbilityRuntime
} // namespace OHOS