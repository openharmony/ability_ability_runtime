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

void ExtensionConfigMgr::Init()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::EXT, "Init begin");
    // clear cached data
    blocklistConfig_.clear();
    extensionBlocklist_.clear();
    extensionEtsBlocklist_.clear();

    // read blocklist from extension_blocklist_config.json
    std::ifstream inFile;
    inFile.open(EXTENSION_BLOCKLIST_FILE_PATH, std::ios::in);
    if (!inFile.is_open()) {
        TAG_LOGE(AAFwkTag::EXT, "read extension config error");
        return;
    }
    nlohmann::json extensionConfig;
    inFile >> extensionConfig;
    if (extensionConfig.is_discarded()) {
        TAG_LOGE(AAFwkTag::EXT, "extension config json discarded error");
        inFile.close();
        return;
    }
    if (!extensionConfig.contains(ExtensionConfigItem::ITEM_NAME_BLOCKLIST)) {
        TAG_LOGE(AAFwkTag::EXT, "extension config file have no blocklist node");
        inFile.close();
        return;
    }
    auto blackList = extensionConfig.at(ExtensionConfigItem::ITEM_NAME_BLOCKLIST);
    std::unordered_set<std::string> currentBlockList;
    for (const auto& item : blackList.items()) {
        if (!blackList[item.key()].is_array()) {
            continue;
        }
        for (const auto& value : blackList[item.key()]) {
            currentBlockList.emplace(value.get<std::string>());
        }
        blocklistConfig_.emplace(item.key(), std::move(currentBlockList));
        currentBlockList.clear();
    }
    inFile.close();
    TAG_LOGD(AAFwkTag::EXT, "Init end");
}

void ExtensionConfigMgr::AddBlockListItem(const std::string& name, int32_t type)
{
    TAG_LOGD(AAFwkTag::EXT, "name: %{public}s, type: %{public}d", name.c_str(), type);
    auto iter = blocklistConfig_.find(name);
    if (iter == blocklistConfig_.end()) {
        TAG_LOGD(AAFwkTag::EXT, "Extension name: %{public}s not exist", name.c_str());
        return;
    }
    extensionBlocklist_.emplace(type, iter->second);
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

    auto moduleChecker = std::make_shared<AppModuleChecker>(extensionType_, extensionBlocklist_);
    runtime->SetModuleLoadChecker(moduleChecker);
    extensionBlocklist_.clear();
}

void ExtensionConfigMgr::GenerateExtensionEtsBlocklists()
{
    if (!extensionEtsBlocklist_.empty()) {
        TAG_LOGD(AAFwkTag::EXT, "extension ets block list not empty.");
        return;
    }
    auto iter = extensionBlocklist_.find(extensionType_);
    if (iter == extensionBlocklist_.end()) {
        TAG_LOGD(AAFwkTag::EXT, "null extension block, extensionType: %{public}d.", extensionType_);
        return;
    }
    for (const auto& module: iter->second) {
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
    if (fileName.size() >= className.size() ||
        className.compare(0, fileName.size(), fileName) != 0 ||
        ((className.compare(0, fileName.size(), fileName) == 0) && className[fileName.size()] != '.')) {
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
    auto callback = [extensionConfigMgrWeak = weak_from_this()](const std::string &className,
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