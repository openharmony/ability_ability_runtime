/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "extension_config_mgr.h"

#include <cctype>
#include <fstream>
#include <nlohmann/json.hpp>

#include "app_module_checker.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"

namespace OHOS::AbilityRuntime {
namespace {
    constexpr char EXTENSION_BLOCKLIST_FILE_PATH[] = "/system/etc/extension_blocklist_config.json";
}

void ExtensionConfigMgr::LoadExtensionBlockList(const std::string &extensionName, int32_t type)
{
    if (type < 0 || type >= EXTENSION_TYPE_UNKNOWN) {
        TAG_LOGE(AAFwkTag::EXT, "Invalid extension type: %{public}d", type);
        return;
    }
    extensionType_ = type;
    {
        std::lock_guard<std::mutex> lock(extensionBlockListMutex_);
        if (extensionBlocklist_.find(extensionType_) != extensionBlocklist_.end()) {
            return;
        }
    }
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::ifstream inFile(EXTENSION_BLOCKLIST_FILE_PATH);
    if (!inFile.is_open()) {
        TAG_LOGW(AAFwkTag::EXT, "Config file not found: %{public}s", EXTENSION_BLOCKLIST_FILE_PATH);
        return;
    }
    nlohmann::json extensionConfig;
    inFile >> extensionConfig;
    inFile.close();
    if (extensionConfig.is_discarded() ||
        !extensionConfig.contains(ExtensionConfigItem::ITEM_NAME_BLOCKLIST)) {
        TAG_LOGE(AAFwkTag::EXT, "Config parse error or missing blocklist");
        return;
    }
    std::unordered_set<std::string> blocklist;
    bool found = false;
    auto blackList = extensionConfig.at(ExtensionConfigItem::ITEM_NAME_BLOCKLIST);
    for (const auto& item : blackList.items()) {
        if (item.key() == extensionName && blackList[item.key()].is_array()) {
            for (const auto& value : blackList[item.key()]) {
                if (value.is_string()) {
                    blocklist.emplace(value.get<std::string>());
                }
            }
            found = true;
            break;
        }
    }
    if (!found) {
        return;
    }
    std::lock_guard<std::mutex> lock(extensionBlockListMutex_);
    auto [iter, success] = extensionBlocklist_.emplace(type, std::move(blocklist));
    if (success) {
        TAG_LOGI(AAFwkTag::EXT, "Loaded type %{public}d, count: %{public}zu", type, iter->second.size());
    }
}

void ExtensionConfigMgr::UpdateRuntimeModuleChecker(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    if (!runtime) {
        TAG_LOGE(AAFwkTag::EXT, "null runtime");
        return;
    }
    TAG_LOGD(AAFwkTag::EXT, "extensionType_: %{public}d", extensionType_);

    if (runtime->GetLanguage() == AbilityRuntime::Runtime::Language::ETS) {
        TAG_LOGD(AAFwkTag::EXT, "ets runtime");
        GenerateExtensionEtsBlocklists();
        SetExtensionEtsCheckCallback(runtime);
    }

    // Copy blocklist with lock protection to avoid holding lock during moduleChecker creation
    std::unordered_map<int32_t, std::unordered_set<std::string>> localBlocklist;
    {
        std::lock_guard<std::mutex> lock(extensionBlockListMutex_);
        localBlocklist = extensionBlocklist_;
        // Note: Don't clear here, let the cache remain for potential reuse
    }

    auto moduleChecker = std::make_shared<AppModuleChecker>(extensionType_, localBlocklist);
    runtime->SetModuleLoadChecker(moduleChecker);
}

void ExtensionConfigMgr::GenerateExtensionEtsBlocklists()
{
    if (!extensionEtsBlocklist_.empty()) {
        TAG_LOGD(AAFwkTag::EXT, "extension ets block list not empty.");
        return;
    }

    // Access extensionBlocklist_ with lock protection
    std::unordered_set<std::string> targetBlocklist;
    {
        std::lock_guard<std::mutex> lock(extensionBlockListMutex_);
        auto iter = extensionBlocklist_.find(extensionType_);
        if (iter == extensionBlocklist_.end()) {
            TAG_LOGW(AAFwkTag::EXT, "No blocklist found for extensionType: %{public}d", extensionType_);
            return;
        }
        targetBlocklist = iter->second;
    }

    for (const auto& module: targetBlocklist) {
        extensionEtsBlocklist_.emplace(module);
    }
}

std::string ExtensionConfigMgr::GetStringAfterRemovePreFix(const std::string &name)
{
    if (!name.empty() && name[0] == '@') {
        size_t dotPos = name.find('.');
        if (dotPos != std::string::npos) {
            return name.substr(dotPos + 1);
        }
    }
    return name;
}

bool ExtensionConfigMgr::CheckEtsModuleLoadable(const std::string &className, const std::string &fileName)
{
    TAG_LOGD(AAFwkTag::EXT, "extensionType: %{public}d, className is %{public}s, fileName is %{public}s",
        extensionType_, className.c_str(), fileName.c_str());
    if (fileName.size() > className.size() ||
        className.compare(0, fileName.size(), fileName) != 0 ||
        (fileName.size() < className.size() && className[fileName.size()] != '.')) {
        TAG_LOGE(AAFwkTag::EXT, "The fileName:%{public}s and className:%{public}s do not match.",
            fileName.c_str(), className.c_str());
        return false;
    }

    std::string fileNameRemovePrefix = GetStringAfterRemovePreFix(fileName);
    for (const auto &blockModuleName: extensionEtsBlocklist_) {
        if (blockModuleName == fileNameRemovePrefix) {
            TAG_LOGE(AAFwkTag::EXT, "%{public}s is in blocklist.", fileName.c_str());
            return false;
        }
    }
    TAG_LOGD(AAFwkTag::EXT, "not in blocklist.");
    return true;
}

void ExtensionConfigMgr::SetExtensionEtsCheckCallback(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    std::function<bool(const std::string &clsName, const std::string &fName)> callback =
        [extensionConfigMgrWeak = weak_from_this()](const std::string &className,
        const std::string &fileName) -> bool {
        auto extensionConfigMgr = extensionConfigMgrWeak.lock();
        if (extensionConfigMgr == nullptr) {
            TAG_LOGE(AAFwkTag::EXT, "null extensionConfigMgr");
            return false;
        }
        return extensionConfigMgr->CheckEtsModuleLoadable(className, fileName);
    };
    runtime->SetExtensionApiCheckCallback(callback);
}
}