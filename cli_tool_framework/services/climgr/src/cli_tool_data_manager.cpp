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

#include "cli_tool_data_manager.h"

#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>
#include <unistd.h>

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace CliTool {
namespace {
constexpr int32_t ERR_OK = 0;
constexpr int32_t ERR_NO_INIT = -1;
constexpr int32_t ERR_FILE_NOT_FOUND = -2;
constexpr int32_t ERR_JSON_PARSE_FAILED = -3;
constexpr int32_t ERR_KVSTORE_NOT_READY = -4;
constexpr int32_t ERR_NAME_NOT_FOUND = -5;
constexpr int32_t CHECK_INTERVAL = 100000; // 100ms
constexpr int32_t MAX_TIMES = 5;           // 5 * 100ms = 500ms

constexpr const char* DEFAULT_REGISTRY_PATH = "/system/bin/cli_tool/cli_tool.json";
constexpr const char* KV_STORE_APP_ID = "cli_tools_storage";
constexpr const char* KV_STORE_STORE_ID = "cli_tools_store";
constexpr const char* CLI_TOOLS_STORAGE_DIR = "/data/service/el1/public/database/ability_manager_service";

const DistributedKv::AppId APP_ID { KV_STORE_APP_ID };
const DistributedKv::StoreId STORE_ID { KV_STORE_STORE_ID };
}

CliToolDataManager &CliToolDataManager::GetInstance()
{
    static CliToolDataManager manager;
    return manager;
}

CliToolDataManager::CliToolDataManager()
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "CliToolDataManager constructor called");
}

CliToolDataManager::~CliToolDataManager()
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "CliToolDataManager destructor called");
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(APP_ID, kvStorePtr_);
    }
}

DistributedKv::Status CliToolDataManager::GetKvStore()
{
    DistributedKv::Options options = { .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .syncable = false,
        .securityLevel = DistributedKv::SecurityLevel::S2,
        .area = DistributedKv::EL1,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = CLI_TOOLS_STORAGE_DIR };

    DistributedKv::Status status = dataManager_.GetSingleKvStore(options, APP_ID, STORE_ID, kvStorePtr_);

    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get KVStore: %{public}d", static_cast<int>(status));
    } else {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "KVStore initialized successfully");
    }

    return status;
}

bool CliToolDataManager::CheckKvStore()
{
    if (kvStorePtr_ != nullptr) {
        return true;
    }

    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        DistributedKv::Status status = GetKvStore();
        if (status == DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
            return true;
        }
        TAG_LOGW(AAFwkTag::CLI_TOOL, "CheckKvStore failed, try times: %{public}d", tryTimes);
        usleep(CHECK_INTERVAL);
        tryTimes--;
    }

    return kvStorePtr_ != nullptr;
}

int32_t CliToolDataManager::EnsureToolsLoaded()
{
    if (toolsLoaded_) {
        return ERR_OK;
    }

    if (!CheckKvStore()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "KVStore not ready");
        return ERR_KVSTORE_NOT_READY;
    }

    int32_t ret = LoadToolsFromFile(DEFAULT_REGISTRY_PATH);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to load tools from default registry: %{public}d", ret);
        return ret;
    }

    toolsLoaded_ = true;
    TAG_LOGI(AAFwkTag::CLI_TOOL, "CliToolDataManager lazy initialization completed");
    return ERR_OK;
}

int32_t CliToolDataManager::LoadToolsFromFile(const std::string &filePath)
{
    std::vector<ToolInfo> tools;
    int32_t ret = ParseJsonFile(filePath, tools);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to parse JSON file: %{public}d", ret);
        return ret;
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Parsed %{public}zu tools from file", tools.size());

    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (!CheckKvStore()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "KVStore not ready");
        return ERR_KVSTORE_NOT_READY;
    }

    // Insert tools one by one using StoreTool
    for (const auto &tool : tools) {
        ret = StoreTool(tool);
        if (ret != ERR_OK) {
            TAG_LOGW(AAFwkTag::CLI_TOOL, "Failed to store tool: %{public}s", tool.name.c_str());
        }
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Successfully loaded and stored %{public}zu tools", tools.size());
    return ERR_OK;
}

int32_t CliToolDataManager::GetAllTools(std::vector<ToolInfo> &tools)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (!CheckKvStore()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "null kvStore");
        return ERR_NO_INIT;
    }

    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = kvStorePtr_->GetEntries(nullptr, allEntries);
    if (status != DistributedKv::Status::SUCCESS) {
        status = RestoreKvStore(status);
        return status;
    }

    tools.clear();
    for (const auto &entry : allEntries) {
        ToolInfo tool;
        int32_t ret = JsonToToolInfo(entry.value.ToString(), tool);
        if (ret != ERR_OK) {
            TAG_LOGW(AAFwkTag::CLI_TOOL, "Failed to parse tool: %{public}s", entry.key.ToString().c_str());
            continue;
        }
        tools.push_back(tool);
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Retrieved %{public}zu tools", tools.size());
    return ERR_OK;
}

int32_t CliToolDataManager::GetToolByName(const std::string &name, ToolInfo &tool)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "GetToolByName called: %{public}s", name.c_str());

    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (!CheckKvStore()) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null kvStore");
        return ERR_NO_INIT;
    }
    DistributedKv::Key key(name);
    DistributedKv::Value value;
    DistributedKv::Status status = kvStorePtr_->Get(key, value);
    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "GetToolByName error: %{public}d", status);
        if (status == DistributedKv::Status::KEY_NOT_FOUND) {
            TAG_LOGW(AAFwkTag::SER_ROUTER, "key not found");
            return ERR_NAME_NOT_FOUND;
        }
        RestoreKvStore(status);
        return status;
    }
    return JsonToToolInfo(value.ToString(), tool);
}

bool CliToolDataManager::ToolExists(const std::string &name)
{
    ToolInfo tool;
    return GetToolByName(name, tool) == ERR_OK;
}

int32_t CliToolDataManager::ParseJsonFile(const std::string &filePath, std::vector<ToolInfo> &tools)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "ParseJsonFile: %{public}s", filePath.c_str());

    std::ifstream file(filePath);
    if (!file.is_open()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to open file: %{public}s", filePath.c_str());
        return ERR_FILE_NOT_FOUND;
    }

    std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    TAG_LOGI(AAFwkTag::CLI_TOOL, "File size: %{public}zu bytes", fileContent.size());

    if (fileContent.empty()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "File is empty");
        return ERR_JSON_PARSE_FAILED;
    }

    // Check for BOM
    if (fileContent.size() >= 3 &&
        (unsigned char)fileContent[0] == 0xEF &&
        (unsigned char)fileContent[1] == 0xBB &&
        (unsigned char)fileContent[2] == 0xBF) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "UTF-8 BOM detected, removing");
        fileContent = fileContent.substr(3);
    }

    nlohmann::json root = nlohmann::json::parse(fileContent, nullptr, false);
    if (root.is_discarded()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "JSON parse failed: invalid JSON format");
        return ERR_JSON_PARSE_FAILED;
    }

    if (!root.is_array()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "JSON root is not an array");
        return ERR_JSON_PARSE_FAILED;
    }

    for (const auto &item : root) {
        ToolInfo tool;

        if (item.contains("name") && item["name"].is_string()) {
            tool.name = item["name"];
        }
        if (item.contains("version") && item["version"].is_string()) {
            tool.version = item["version"];
        }
        if (item.contains("description") && item["description"].is_string()) {
            tool.description = item["description"];
        }
        if (item.contains("permissions") && item["permissions"].is_array()) {
            for (const auto &perm : item["permissions"]) {
                if (perm.is_string()) {
                    tool.permissions.push_back(perm);
                }
            }
        }
        if (item.contains("executablePath") && item["executablePath"].is_string()) {
            tool.executablePath = item["executablePath"];
        }
        if (item.contains("inputSchema") && item["inputSchema"].is_string()) {
            tool.inputSchema = item["inputSchema"];
        }
        if (item.contains("outputSchema") && item["outputSchema"].is_string()) {
            tool.outputSchema = item["outputSchema"];
        }
        if (item.contains("argMapping") && item["argMapping"].is_string()) {
            tool.argMapping = item["argMapping"];
        }
        if (item.contains("eventSchemas") && item["eventSchemas"].is_string()) {
            tool.eventSchemas = item["eventSchemas"];
        }
        if (item.contains("timeout") && item["timeout"].is_number()) {
            tool.timeout = item["timeout"];
        }
        if (item.contains("eventTypes") && item["eventTypes"].is_array()) {
            for (const auto &event : item["eventTypes"]) {
                if (event.is_string()) {
                    tool.eventTypes.push_back(event);
                }
            }
        }
        if (item.contains("registeredTime") && item["registeredTime"].is_number()) {
            tool.registeredTime = item["registeredTime"];
        } else {
            tool.registeredTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
        if (item.contains("enabled") && item["enabled"].is_boolean()) {
            tool.enabled = item["enabled"];
        } else {
            tool.enabled = true;
        }
        if (item.contains("hasSubcommands") && item["hasSubcommands"].is_boolean()) {
            tool.hasSubcommands = item["hasSubcommands"];
        } else {
            tool.hasSubcommands = false;
        }
        if (item.contains("subcommands") && item["subcommands"].is_string()) {
            tool.subcommands = item["subcommands"];
        }

        tools.push_back(tool);
        TAG_LOGI(AAFwkTag::CLI_TOOL, "Parsed tool: %{public}s", tool.name.c_str());
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Successfully parsed %{public}zu tools", tools.size());
    return ERR_OK;
}

std::string CliToolDataManager::ToolInfoToJson(const ToolInfo &tool)
{
    nlohmann::json j;
    j["name"] = tool.name;
    j["version"] = tool.version;
    j["description"] = tool.description;
    j["executablePath"] = tool.executablePath;
    j["permissions"] = tool.permissions;
    j["inputSchema"] = tool.inputSchema;
    j["outputSchema"] = tool.outputSchema;
    j["argMapping"] = tool.argMapping;
    j["eventSchemas"] = tool.eventSchemas;
    j["timeout"] = tool.timeout;
    j["eventTypes"] = tool.eventTypes;
    j["registeredTime"] = tool.registeredTime;
    j["enabled"] = tool.enabled;
    j["hasSubcommands"] = tool.hasSubcommands;
    j["subcommands"] = tool.subcommands;
    return j.dump();
}

int32_t CliToolDataManager::JsonToToolInfo(const std::string &jsonStr, ToolInfo &tool)
{
    nlohmann::json j = nlohmann::json::parse(jsonStr, nullptr, false);
    if (j.is_discarded()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "JSON parse failed: invalid JSON format");
        return ERR_JSON_PARSE_FAILED;
    }

    if (j.contains("name") && j["name"].is_string()) {
        tool.name = j["name"];
    }
    if (j.contains("version") && j["version"].is_string()) {
        tool.version = j["version"];
    }
    if (j.contains("description") && j["description"].is_string()) {
        tool.description = j["description"];
    }
    if (j.contains("executablePath") && j["executablePath"].is_string()) {
        tool.executablePath = j["executablePath"];
    }
    if (j.contains("permissions") && j["permissions"].is_array()) {
        tool.permissions = j["permissions"];
    }
    if (j.contains("inputSchema") && j["inputSchema"].is_string()) {
        tool.inputSchema = j["inputSchema"];
    }
    if (j.contains("outputSchema") && j["outputSchema"].is_string()) {
        tool.outputSchema = j["outputSchema"];
    }
    if (j.contains("argMapping") && j["argMapping"].is_string()) {
        tool.argMapping = j["argMapping"];
    }
    if (j.contains("eventSchemas") && j["eventSchemas"].is_string()) {
        tool.eventSchemas = j["eventSchemas"];
    }
    if (j.contains("timeout") && j["timeout"].is_number()) {
        tool.timeout = j["timeout"];
    }
    if (j.contains("eventTypes") && j["eventTypes"].is_array()) {
        tool.eventTypes = j["eventTypes"];
    }
    if (j.contains("registeredTime") && j["registeredTime"].is_number()) {
        tool.registeredTime = j["registeredTime"];
    }
    if (j.contains("enabled") && j["enabled"].is_boolean()) {
        tool.enabled = j["enabled"];
    }
    if (j.contains("hasSubcommands") && j["hasSubcommands"].is_boolean()) {
        tool.hasSubcommands = j["hasSubcommands"];
    }
    if (j.contains("subcommands") && j["subcommands"].is_string()) {
        tool.subcommands = j["subcommands"];
    }

    return ERR_OK;
}

std::string CliToolDataManager::ToolsToJsonArray(const std::vector<ToolInfo> &tools)
{
    nlohmann::json j = nlohmann::json::array();
    for (const auto &tool : tools) {
        nlohmann::json item;
        item["name"] = tool.name;
        item["version"] = tool.version;
        item["description"] = tool.description;
        item["executablePath"] = tool.executablePath;
        item["permissions"] = tool.permissions;
        item["inputSchema"] = tool.inputSchema;
        item["outputSchema"] = tool.outputSchema;
        item["argMapping"] = tool.argMapping;
        item["eventSchemas"] = tool.eventSchemas;
        item["timeout"] = tool.timeout;
        item["eventTypes"] = tool.eventTypes;
        item["registeredTime"] = tool.registeredTime;
        item["enabled"] = tool.enabled;
        item["hasSubcommands"] = tool.hasSubcommands;
        item["subcommands"] = tool.subcommands;
        j.push_back(item);
    }
    return j.dump();
}

int32_t CliToolDataManager::JsonArrayToTools(const std::string &jsonStr, std::vector<ToolInfo> &tools)
{
    nlohmann::json j = nlohmann::json::parse(jsonStr, nullptr, false);
    if (j.is_discarded()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "JSON parse failed: invalid JSON format");
        return ERR_JSON_PARSE_FAILED;
    }

    if (!j.is_array()) {
        return ERR_JSON_PARSE_FAILED;
    }

    tools.clear();
    for (const auto &item : j) {
        ToolInfo tool;
        int32_t ret = JsonToToolInfo(item.dump(), tool);
        if (ret != ERR_OK) {
            TAG_LOGW(AAFwkTag::CLI_TOOL, "Failed to parse tool item");
            continue;
        }
        tools.push_back(tool);
    }

    return ERR_OK;
}

int32_t CliToolDataManager::StoreTool(const ToolInfo &tool)
{
    DistributedKv::Key key(tool.name);
    DistributedKv::Value value(ToolInfoToJson(tool));
    DistributedKv::Status status = kvStorePtr_->Put(key, value);

    if (status != DistributedKv::Status::SUCCESS) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to store tool: %{public}s, status: %{public}d",
            tool.name.c_str(), static_cast<int>(status));
        return -1;
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Stored tool: %{public}s", tool.name.c_str());
    return ERR_OK;
}

int32_t CliToolDataManager::QueryToolSummaries(std::vector<ToolSummary> &summaries)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (!CheckKvStore()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "null kvStore");
        return ERR_NO_INIT;
    }

    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = kvStorePtr_->GetEntries(nullptr, allEntries);
    if (status != DistributedKv::Status::SUCCESS) {
        status = RestoreKvStore(status);
        return status;
    }

    summaries.clear();
    for (const auto &entry : allEntries) {
        ToolInfo tool;
        int32_t ret = JsonToToolInfo(entry.value.ToString(), tool);
        if (ret != ERR_OK) {
            TAG_LOGW(AAFwkTag::CLI_TOOL, "Failed to parse tool: %{public}s", entry.key.ToString().c_str());
            continue;
        }

        ToolSummary summary;
        summary.name = tool.name;
        summary.version = tool.version;
        summary.description = tool.description;
        summaries.push_back(summary);
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Retrieved %{public}zu tool summaries", summaries.size());
    return ERR_OK;
}

int32_t CliToolDataManager::RegisterTool(const ToolInfo &tool)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    TAG_LOGI(AAFwkTag::CLI_TOOL, "RegisterTool called: %{public}s", tool.name.c_str());

    if (!CheckKvStore()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "KVStore not ready");
        return ERR_KVSTORE_NOT_READY;
    }

    int32_t ret = StoreTool(tool);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to store tool: %{public}d", ret);
        return ret;
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Successfully registered tool: %{public}s", tool.name.c_str());
    return ERR_OK;
}

DistributedKv::Status CliToolDataManager::RestoreKvStore(DistributedKv::Status status)
{
    if (status == DistributedKv::Status::DATA_CORRUPTED) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "KVStore data corrupted, deleting and recreating");
        DistributedKv::Options options = {
            .createIfMissing = true,
            .encrypt = false,
            .autoSync = false,
            .syncable = false,
            .securityLevel = DistributedKv::SecurityLevel::S2,
            .area = DistributedKv::EL1,
            .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
            .baseDir = CLI_TOOLS_STORAGE_DIR
        };
        dataManager_.DeleteKvStore(APP_ID, STORE_ID, options.baseDir);
        status = dataManager_.GetSingleKvStore(options, APP_ID, STORE_ID, kvStorePtr_);
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Recreated KVStore with status: %{public}d", static_cast<int>(status));
    }
    return status;
}
} // namespace CliTool
} // namespace OHOS
