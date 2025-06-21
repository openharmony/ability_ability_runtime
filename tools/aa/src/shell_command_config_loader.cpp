/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "shell_command_config_loader.h"
#include <fstream>
#include <sstream>
#include <unistd.h>
#include "cJSON.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
namespace {
    constexpr const char* AA_TOOL_COMMAND_LIST = "command_list";
    constexpr static int  COMMANDS_MAX_SIZE = 100;
}

bool ShellCommandConfigLoader::configState_ = false;
std::set<std::string> ShellCommandConfigLoader::commands_ = {};

bool ShellCommandConfigLoader::ReadConfig(const std::string &filePath)
{
    TAG_LOGD(AAFwkTag::AA_TOOL, "called");
    if (configState_) {
        TAG_LOGI(AAFwkTag::AA_TOOL, "config read");
        return true;
    }

    if (filePath.empty()) {
        TAG_LOGE(AAFwkTag::AA_TOOL, "empty file path");
        return false;
    }

    if (access(filePath.c_str(), F_OK) != 0) {
        TAG_LOGE(AAFwkTag::AA_TOOL, "access file: %{private}s failed", filePath.c_str());
        return false;
    }

    std::ifstream inFile;
    inFile.open(filePath, std::ios::in);
    if (!inFile.is_open()) {
        TAG_LOGI(AAFwkTag::AA_TOOL, "read aa config error");
        return false;
    }
    std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    cJSON *aaJson = cJSON_Parse(fileContent.c_str());
    if (aaJson == nullptr) {
        TAG_LOGI(AAFwkTag::AA_TOOL, "json parse error");
        return false;
    }

    if (cJSON_IsNull(aaJson) || !cJSON_IsObject(aaJson)) {
        TAG_LOGI(AAFwkTag::AA_TOOL, "invalid jsonObj");
        return false;
    }

    cJSON *commonListItem = cJSON_GetObjectItem(aaJson, AA_TOOL_COMMAND_LIST);
    if (commonListItem == nullptr) {
        TAG_LOGI(AAFwkTag::AA_TOOL, "config not contains the key");
        cJSON_Delete(aaJson);
        return false;
    }

    if (!cJSON_IsArray(commonListItem)) {
        TAG_LOGI(AAFwkTag::AA_TOOL, "invalid command obj");
        cJSON_Delete(aaJson);
        return false;
    }
    int commonListSize = cJSON_GetArraySize(commonListItem);
    if (commonListSize <= 0) {
        TAG_LOGI(AAFwkTag::AA_TOOL, "invalid command obj size");
        cJSON_Delete(aaJson);
        return false;
    }
    if (commonListSize > COMMANDS_MAX_SIZE) {
        TAG_LOGI(AAFwkTag::AA_TOOL, "command obj size overflow");
        cJSON_Delete(aaJson);
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mtxRead_);
    for (int i = 0; i < commonListSize; i++) {
        cJSON *cmdItem = cJSON_GetArrayItem(commonListItem, i);
        if (cmdItem == nullptr || !cJSON_IsString(cmdItem)) {
            continue;
        }
        std::string cmd = cmdItem->valuestring;
        TAG_LOGD(AAFwkTag::AA_TOOL, "add cmd: %{public}s", cmd.c_str());
        commands_.emplace(cmd);
    }

    cJSON_Delete(aaJson);
    TAG_LOGI(AAFwkTag::AA_TOOL, "read config success");
    configState_ = true;
    return true;
}
}  // namespace AAFwk
}  // namespace OHOS