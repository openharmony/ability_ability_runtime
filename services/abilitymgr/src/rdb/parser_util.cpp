/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "parser_util.h"

#include <fstream>
#include <unistd.h>

#include "config_policy_utils.h"
#include "hilog_tag_wrapper.h"
#include "json_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *DEFAULT_PRE_BUNDLE_ROOT_DIR = "/system";
constexpr const char *PRODUCT_SUFFIX = "/etc/app";
constexpr const char *INSTALL_LIST_CAPABILITY_CONFIG = "/install_list_capability.json";
constexpr const char *INSTALL_LIST = "install_list";
constexpr const char *BUNDLE_NAME = "bundleName";
constexpr const char *KEEP_ALIVE = "keepAlive";
constexpr const char *KEEP_ALIVE_ENABLE = "keepAliveEnable";
constexpr const char *KEEP_ALIVE_CONFIGURED_LIST = "keepAliveConfiguredList";

} // namespace
ParserUtil &ParserUtil::GetInstance()
{
    static ParserUtil instance;
    return instance;
}

void ParserUtil::GetResidentProcessRawData(std::vector<std::tuple<std::string, std::string, std::string>> &list)
{
    std::vector<std::string> rootDirList;
    GetPreInstallRootDirList(rootDirList);

    for (auto &root : rootDirList) {
        auto fileDir = root.append(PRODUCT_SUFFIX).append(INSTALL_LIST_CAPABILITY_CONFIG);
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Search file dir : %{public}s", fileDir.c_str());
        ParsePreInstallAbilityConfig(fileDir, list);
    }
}

void ParserUtil::ParsePreInstallAbilityConfig(
    const std::string &filePath, std::vector<std::tuple<std::string, std::string, std::string>> &list)
{
    cJSON *jsonBuf = nullptr;
    if (!ReadFileIntoJson(filePath, jsonBuf)) {
        return;
    }

    if (jsonBuf == nullptr) {
        return;
    }

    FilterInfoFromJson(jsonBuf, list);

    cJSON_Delete(jsonBuf);
}

bool ParserUtil::FilterInfoFromJson(
    cJSON *jsonBuf, std::vector<std::tuple<std::string, std::string, std::string>> &list)
{
    if (jsonBuf == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "format error");
        return false;
    }

    cJSON *arrays = cJSON_GetObjectItem(jsonBuf, INSTALL_LIST);
    if (arrays == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "installList absent");
        return false;
    }
    if (!cJSON_IsArray(arrays)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not found");
        return false;
    }

    std::string bundleName;
    std::string KeepAliveEnable = "1";
    std::string KeepAliveConfiguredList;
    int size = cJSON_GetArraySize(arrays);
    for (int i = 0; i < size; i++) {
        cJSON *array = cJSON_GetArrayItem(arrays, i);
        if (array == nullptr || !cJSON_IsObject(array)) {
            continue;
        }

        // Judgment logic exists, not found, not bool, not resident process
        cJSON *keepAliveItem = cJSON_GetObjectItem(array, KEEP_ALIVE);
        if (keepAliveItem == nullptr || !cJSON_IsBool(keepAliveItem) || keepAliveItem->type != cJSON_True) {
            continue;
        }

        cJSON *bundleNameItem = cJSON_GetObjectItem(array, BUNDLE_NAME);
        if (bundleNameItem == nullptr || !cJSON_IsString(bundleNameItem)) {
            continue;
        }

        bundleName = bundleNameItem->valuestring;

        cJSON *keepAliveEnableItem = cJSON_GetObjectItem(array, KEEP_ALIVE_ENABLE);
        if (keepAliveEnableItem != nullptr || cJSON_IsBool(keepAliveEnableItem)) {
            bool val = keepAliveEnableItem->type == cJSON_True;
            KeepAliveEnable = std::to_string(val);
        }

        cJSON *keepAliveConfiguredListItem = cJSON_GetObjectItem(array, KEEP_ALIVE_CONFIGURED_LIST);
        if (keepAliveConfiguredListItem != nullptr || cJSON_IsArray(keepAliveConfiguredListItem)) {
            // Save directly in the form of an array and parse it when in use
            KeepAliveConfiguredList = AAFwk::JsonUtils::GetInstance().ToString(keepAliveConfiguredListItem);
        }

        list.emplace_back(std::make_tuple(bundleName, KeepAliveEnable, KeepAliveConfiguredList));
        bundleName.clear();
        KeepAliveEnable = "1";
        KeepAliveConfiguredList.clear();
    }

    return true;
}

void ParserUtil::GetPreInstallRootDirList(std::vector<std::string> &rootDirList)
{
    auto cfgDirList = GetCfgDirList();
    if (cfgDirList != nullptr) {
        for (const auto &cfgDir : cfgDirList->paths) {
            if (cfgDir == nullptr) {
                continue;
            }
            rootDirList.emplace_back(cfgDir);
        }

        FreeCfgDirList(cfgDirList);
    }
    bool ret = std::find(rootDirList.begin(), rootDirList.end(), DEFAULT_PRE_BUNDLE_ROOT_DIR) != rootDirList.end();
    if (!ret) {
        rootDirList.emplace_back(DEFAULT_PRE_BUNDLE_ROOT_DIR);
    }
}

bool ParserUtil::ReadFileIntoJson(const std::string &filePath, cJSON *&jsonBuf)
{
    if (access(filePath.c_str(), F_OK) != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "path not exist");
        return false;
    }

    if (filePath.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "empty path");
        return false;
    }

    char path[PATH_MAX] = {0};
    if (realpath(filePath.c_str(), path) == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "realpath error:%{public}d", errno);
        return false;
    }

    std::ifstream fin(path);
    if (!fin.is_open()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "path exception");
        return false;
    }

    fin.seekg(0, std::ios::end);
    int64_t size = fin.tellg();
    if (size <= 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "empty file");
        fin.close();
        return false;
    }

    fin.seekg(0, std::ios::beg);
    std::string fileContent((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    jsonBuf = cJSON_Parse(fileContent.c_str());
    if (jsonBuf == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "bad profile");
        return false;
    }
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS