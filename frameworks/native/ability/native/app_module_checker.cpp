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

#include "app_module_checker.h"

#include "hilog_tag_wrapper.h"
#include "module_checker_delegate.h"
#include "utils/log.h"

#include <algorithm>
#include <cctype>
#include <string>

AppModuleChecker::AppModuleChecker(int32_t extensionType,
    const std::unordered_map<int32_t, std::unordered_set<std::string>>& extensionBlocklist)
{
    auto iter = extensionBlocklist.find(extensionType);
    if (iter == extensionBlocklist.end()) {
        return;
    }
    TAG_LOGD(AAFwkTag::ABILITY, "transform begin");
    for (const auto& module: iter->second) {
        std::string lowermodule;
        lowermodule.reserve(module.size());
        std::transform(module.cbegin(), module.cend(), std::back_inserter(lowermodule),
            [](unsigned char c) { return std::tolower(c); });
            blockList_.emplace(std::move(lowermodule));
    }
    TAG_LOGD(AAFwkTag::ABILITY, "transform end");
}

bool AppModuleChecker::CheckModuleLoadable(const char *moduleName,
                                           std::unique_ptr<ApiAllowListChecker> &apiAllowListChecker,
                                           bool isAppModule)
{
    apiAllowListChecker = nullptr;
    TAG_LOGD(AAFwkTag::ABILITY, "check blocklist, moduleName:%{public}s", moduleName);

    std::string strModuleName(moduleName);
    std::string lowerModuleName;
    lowerModuleName.reserve(strModuleName.size());
    std::transform(strModuleName.cbegin(), strModuleName.cend(), std::back_inserter(lowerModuleName),
        [](unsigned char c) { return std::tolower(c); });
    if (blockList_.find(lowerModuleName) == blockList_.end()) {
        return true;
    }
    return false;
}

bool AppModuleChecker::DiskCheckOnly()
{
    return false;
}