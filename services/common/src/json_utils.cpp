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

#include "json_utils.h"
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <regex>

#include "config_policy_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
bool JsonUtils::LoadConfiguration(const std::string& path, cJSON *&jsonBuf, const std::string& defaultPath)
{
    std::string configPath = GetConfigPath(path, defaultPath);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "config path is: %{public}s", configPath.c_str());
    if (!ReadFileInfoJson(configPath, jsonBuf)) {
        return false;
    }
    return true;
}

std::string JsonUtils::GetConfigPath(const std::string& path, const std::string& defaultPath)
{
    char buf[MAX_PATH_LEN] = { 0 };
    char *configPath = GetOneCfgFile(path.c_str(), buf, MAX_PATH_LEN);
    if (configPath == nullptr || configPath[0] == '\0' || strlen(configPath) > MAX_PATH_LEN) {
        return defaultPath;
    }
    return configPath;
}

bool JsonUtils::ReadFileInfoJson(const std::string &filePath, cJSON *&jsonBuf)
{
    if (access(filePath.c_str(), F_OK) != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "deepLink config not exist");
        return false;
    }

    if (filePath.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "filePath empty");
        return false;
    }

    char path[PATH_MAX] = {0};
    if (realpath(filePath.c_str(), path) == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "realpath error, errno: %{public}d", errno);
        return false;
    }

    std::fstream in;
    char errBuf[256];
    errBuf[0] = '\0';
    in.open(path, std::ios_base::in);
    if (!in.is_open()) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        TAG_LOGE(AAFwkTag::ABILITYMGR, "file not open: %{public}s", errBuf);
        return false;
    }

    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "empty file");
        in.close();
        return false;
    }

    in.seekg(0, std::ios::beg);
    std::string fileContent((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    jsonBuf = cJSON_Parse(fileContent.c_str());
    if (jsonBuf == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "bad profile file");
        return false;
    }

    return true;
}

bool JsonUtils::IsEqual(cJSON *jsonObject, const std::string &key, const std::string &value, bool checkEmpty)
{
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item != nullptr && cJSON_IsString(item)) {
        std::string jsonValue = item->valuestring;
        if (checkEmpty && !jsonValue.empty() && jsonValue != value) {
            return false;
        } else if (value != jsonValue) {
            return false;
        }
    }
    return true;
}

bool JsonUtils::IsEqual(cJSON *jsonObject, const std::string &key, int32_t value)
{
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item != nullptr && cJSON_IsNumber(item)) {
        int32_t jsonValue = static_cast<int32_t>(item->valuedouble);
        if (value != jsonValue) {
            return false;
        }
    }
    return true;
}

std::optional<bool> JsonUtils::JsonToOptionalBool(const cJSON *jsonObject, const std::string &key)
{
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item != nullptr && cJSON_IsBool(item)) {
        return item->type == cJSON_True;
    }
    return std::nullopt;
}

std::string JsonUtils::ToString(const cJSON *jsonObject)
{
    if (jsonObject == nullptr) {
        return {};
    }
    char *str = cJSON_PrintUnformatted(jsonObject);
    if (str == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json string failed");
        return {};
    }
    std::string jsonStr(str);
    cJSON_free(str);
    return jsonStr;
}
}  // namespace AAFwk
}  // namespace OHOS