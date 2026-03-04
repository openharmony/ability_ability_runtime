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

#include "madvise_utils.h"

#include "cJSON.h"
#include <algorithm>
#include <chrono>
#include <libgen.h>
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <unordered_set>
#include <string>
#include <vector>

#include "config_policy_utils.h"
#include "hilog_tag_wrapper.h"
#include "vma_utils.h"

namespace {
constexpr const char* MADVISE_CONFIG_DEFAULT_FILE_PATH = "/system/etc/madvise_config.json";
constexpr const char* MADVISE_CONFIG_FILE_PATH = "/etc/madvise_config.json";
constexpr int32_t PERMS_INDEX_0 = 0;
constexpr int32_t PERMS_INDEX_1 = 1;
constexpr int32_t PERMS_INDEX_2 = 2;
constexpr int32_t PERMS_INDEX_3 = 3;
constexpr int32_t PERMS_LEN = 4;

enum class LibraryType {
    UNKNOWN = 0,
    ELF,
    VMA
};

struct LibraryConfig {
    std::string name;
    LibraryType type;
    std::vector<unsigned long> hotPageOffsets;
};

struct AppConfig {
    std::string bundleName;
    std::vector<LibraryConfig> libraries;
};

struct MadviseConfig {
    std::vector<AppConfig> apps;

    bool IsValid() const
    {
        return !apps.empty();
    }

    const AppConfig* FindApp(const char* bundleName) const
    {
        if (!bundleName || strlen(bundleName) == 0) {
            return nullptr;
        }
        for (const auto& app : apps) {
            if (app.bundleName == bundleName) {
                return &app;
            }
        }
        return nullptr;
    }
};

LibraryType ParseLibraryType(const std::string& typeStr)
{
    if (typeStr == "elf") {
        return LibraryType::ELF;
    } else if (typeStr == "vma") {
        return LibraryType::VMA;
    }
    return LibraryType::UNKNOWN;
}

MadviseConfig LoadConfigFromFile()
{
    MadviseConfig config;
    std::string configPath = OHOS::AbilityRuntime::MadviseUtil::GetConfigPath();
    char resolvedPath[PATH_MAX] = {0};
    if (realpath(configPath.c_str(), resolvedPath) == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "realpath error, errno: %{public}d", errno);
        return config;
    }
    FILE* file = fopen(resolvedPath, "r");
    if (!file) {
        TAG_LOGE(AAFwkTag::ABILITY, "Failed to open config file");
        return config;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        TAG_LOGE(AAFwkTag::ABILITY, "Failed to seek file end");
        if (fclose(file) != 0) {
            TAG_LOGE(AAFwkTag::ABILITY, "Failed to close file");
        }
        return config;
    }
    long fileSize = ftell(file);
    if (fileSize <= 0) {
        TAG_LOGE(AAFwkTag::ABILITY, "Config file is empty");
        if (fclose(file) != 0) {
            TAG_LOGE(AAFwkTag::ABILITY, "Failed to close file");
        }
        return config;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        TAG_LOGE(AAFwkTag::ABILITY, "Failed to seek file begin");
        if (fclose(file) != 0) {
            TAG_LOGE(AAFwkTag::ABILITY, "Failed to close file");
        }
        return config;
    }
    std::string content;
    content.resize(fileSize);
    size_t readSize = fread(&content[0], 1, fileSize, file);
    if (fclose(file) != 0) {
        TAG_LOGE(AAFwkTag::ABILITY, "Failed to close file");
    }
    if (readSize != static_cast<size_t>(fileSize)) {
        TAG_LOGE(AAFwkTag::ABILITY, "Failed to read config file");
        return config;
    }
    cJSON* root = cJSON_Parse(content.c_str());
    if (!root) {
        TAG_LOGE(AAFwkTag::ABILITY, "Failed to parse JSON config");
        return config;
    }
    cJSON* appsArray = cJSON_GetObjectItemCaseSensitive(root, "apps");
    if (!cJSON_IsArray(appsArray)) {
        TAG_LOGE(AAFwkTag::ABILITY, "Invalid config format: 'apps' not found or not an array");
        cJSON_Delete(root);
        return config;
    }
    cJSON* appItem = nullptr;
    cJSON_ArrayForEach(appItem, appsArray) {
        AppConfig appConfig;
        cJSON* bundleNameItem = cJSON_GetObjectItemCaseSensitive(appItem, "bundle_name");
        if (!bundleNameItem || !cJSON_IsString(bundleNameItem) || !bundleNameItem->valuestring) {
            continue;
        }
        appConfig.bundleName = bundleNameItem->valuestring;
        if (appConfig.bundleName.empty()) {
            continue;
        }
        cJSON* libsArray = cJSON_GetObjectItemCaseSensitive(appItem, "libraries");
        if (!cJSON_IsArray(libsArray)) {
            continue;
        }
        cJSON* libItem = nullptr;
        cJSON_ArrayForEach(libItem, libsArray) {
            LibraryConfig libConfig;
            cJSON* nameItem = cJSON_GetObjectItemCaseSensitive(libItem, "name");
            if (!nameItem || !cJSON_IsString(nameItem) || !nameItem->valuestring) {
                continue;
            }
            libConfig.name = nameItem->valuestring;
            if (libConfig.name.empty()) {
                continue;
            }
            cJSON* typeItem = cJSON_GetObjectItemCaseSensitive(libItem, "type");
            if (!typeItem || !cJSON_IsString(typeItem) || !typeItem->valuestring) {
                continue;
            }
            libConfig.type = ParseLibraryType(typeItem->valuestring);
            if (libConfig.type == LibraryType::UNKNOWN) {
                continue;
            }
            appConfig.libraries.push_back(libConfig);
        }
        if (!appConfig.libraries.empty()) {
            config.apps.push_back(appConfig);
        }
    }
    cJSON_Delete(root);
    TAG_LOGD(AAFwkTag::ABILITY, "Loaded madvise config: %{public}zu apps", config.apps.size());
    return config;
}

int32_t ApplyMadviseWithConfig(const char* bundleName, const MadviseConfig& config)
{
    if (!bundleName || strlen(bundleName) == 0) {
        TAG_LOGE(AAFwkTag::ABILITY, "Invalid bundle name: null or empty");
        return 0;
    }
    const AppConfig* appConfig = config.FindApp(bundleName);
    if (!appConfig) {
        TAG_LOGD(AAFwkTag::ABILITY, "No config found for bundle: %{public}s", bundleName);
        return 0;
    }
    TAG_LOGD(AAFwkTag::ABILITY, "Applying madvise for bundle: %{public}s, libraries: %{public}zu",
        bundleName, appConfig->libraries.size());
    int32_t successCount = 0;
    std::vector<std::string> vmaLibNames;
    for (const auto& libConfig : appConfig->libraries) {
        bool libSuccess = false;
        if (libConfig.type == LibraryType::ELF) {
            TAG_LOGD(AAFwkTag::ABILITY, "Applying ELF madvise for: %{public}s", libConfig.name.c_str());
            libSuccess = OHOS::AbilityRuntime::MadviseUtil::MadviseSingleLibrary(libConfig.name.c_str());
            if (libSuccess) {
                successCount++;
            }
        } else if (libConfig.type == LibraryType::VMA) {
            TAG_LOGD(AAFwkTag::ABILITY, "Adding VMA madvise for: %{public}s", libConfig.name.c_str());
            vmaLibNames.push_back(libConfig.name);
        } else {
            TAG_LOGW(AAFwkTag::ABILITY, "Unknown library type for: %{public}s", libConfig.name.c_str());
            continue;
        }
    }
    if (!vmaLibNames.empty()) {
        successCount += OHOS::AbilityRuntime::MadviseUtil::MadviseGeneralFiles(vmaLibNames);
    }
    TAG_LOGI(AAFwkTag::ABILITY,
        "Madvise completed for bundle %{public}s: %{public}d/%{public}zu libraries succeeded",
        bundleName, successCount, appConfig->libraries.size());
    return successCount;
}
}

struct MadviseData {
    int32_t successCount;
    int32_t failCount;
    const char* targetLibName;
};

static int32_t MadvisePhdrCallback(struct dl_phdr_info *info, size_t size, void *data)
{
    if (!info || !data) {
        return 0;
    }
    MadviseData* madviseData = static_cast<MadviseData*>(data);
    if (!madviseData->targetLibName || strlen(madviseData->targetLibName) == 0) {
        return 0;
    }
    const char* currentLibName = info->dlpi_name;
    if (!currentLibName || strlen(currentLibName) == 0) {
        return 0;
    }
    if (strstr(currentLibName, madviseData->targetLibName) == nullptr) {
        return 0;
    }
    TAG_LOGD(AAFwkTag::ABILITY, "Found target library: %{public}s", currentLibName);
    for (int32_t i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        bool isReadable = (phdr->p_flags & PF_R);
        bool isWritable = (phdr->p_flags & PF_W);
        if (!isReadable || isWritable) {
            continue;
        }
        void* startAddr = reinterpret_cast<void*>(info->dlpi_addr + phdr->p_vaddr);
        size_t len = phdr->p_memsz;
        size_t pageSize = static_cast<size_t>(getpagesize());
        void* alignedStart = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(startAddr) & ~(pageSize - 1));
        size_t alignedLen = (reinterpret_cast<uintptr_t>(startAddr) + len + pageSize - 1) & ~(pageSize - 1);
        alignedLen -= reinterpret_cast<uintptr_t>(alignedStart);
        char perms[4] = "---";
        if (phdr->p_flags & PF_R) {
            perms[PERMS_INDEX_0] = 'r';
        }
        if (phdr->p_flags & PF_W) {
            perms[PERMS_INDEX_1] = 'w';
        }
        if (phdr->p_flags & PF_X) {
            perms[PERMS_INDEX_2] = 'x';
        }
        perms[PERMS_INDEX_3] = '\0';
        TAG_LOGD(AAFwkTag::ABILITY,
            "madvise: lib=%{public}s, perms=%{public}s, len=%{public}zu, alignedLen=%{public}zu",
            info->dlpi_name ? info->dlpi_name : "unknown", perms, len, alignedLen);
        int32_t result = madvise(alignedStart, alignedLen, MADV_DONTNEED);
        if (result == 0) {
            TAG_LOGD(AAFwkTag::ABILITY, "madvise success: len=%{public}zu", alignedLen);
            madviseData->successCount++;
        } else {
            TAG_LOGE(AAFwkTag::ABILITY, "madvise failed: len=%{public}zu, errno=%{public}d", alignedLen, errno);
            madviseData->failCount++;
        }
    }
    return 0;
}

namespace OHOS {
namespace AbilityRuntime {
namespace MadviseUtil {
bool MadviseSingleLibrary(const char* libName)
{
    if (!libName || strlen(libName) == 0) {
        TAG_LOGE(AAFwkTag::ABILITY, "Invalid library name: empty string");
        return false;
    }
    TAG_LOGD(AAFwkTag::ABILITY, "MadviseSingleLibrary called for library=%{public}s", libName);
    MadviseData madviseData = {0, 0, libName};
    dl_iterate_phdr(MadvisePhdrCallback, &madviseData);
    TAG_LOGD(AAFwkTag::ABILITY,
        "madvise completed for lib=%{public}s: successCount=%{public}d, failCount=%{public}d",
        libName, madviseData.successCount, madviseData.failCount);
    return (madviseData.successCount > 0);
}

static bool ApplyMadviseToRegion(const OHOS::AbilityRuntime::VmaUtil::VMARegion& region, const char* filename)
{
    if (strlen(region.perms) < PERMS_LEN) {
        TAG_LOGI(AAFwkTag::ABILITY, "Skipping invalid perms: %{public}s", region.perms);
        return false;
    }
    bool isReadable = (region.perms[0] == 'r');
    bool isWritable = (region.perms[1] == 'w');
    if (!isReadable || isWritable) {
        return false;
    }
    size_t pageSize = static_cast<size_t>(getpagesize());
    void* startAddr = reinterpret_cast<void*>(region.start);
    void* alignedStart = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(startAddr) & ~(pageSize - 1));
    void* endAddr = reinterpret_cast<void*>(region.end);
    size_t alignedLen = (reinterpret_cast<uintptr_t>(endAddr) + pageSize - 1) & ~(pageSize - 1);
    alignedLen -= reinterpret_cast<uintptr_t>(alignedStart);
    TAG_LOGD(AAFwkTag::ABILITY,
        "madvise: file=%{private}s, perms=%{public}s, len=%{public}zu, alignedLen=%{public}zu",
        filename ? filename : "unknown", region.perms, region.size, alignedLen);
    int32_t result = madvise(alignedStart, alignedLen, MADV_DONTNEED);
    if (result == 0) {
        TAG_LOGD(AAFwkTag::ABILITY, "madvise success: len=%{public}zu", alignedLen);
        return true;
    } else {
        TAG_LOGE(AAFwkTag::ABILITY, "madvise failed: len=%{public}zu, errno=%{public}d", alignedLen, errno);
        return false;
    }
}

static int32_t ProcessVmaRegions(const std::vector<OHOS::AbilityRuntime::VmaUtil::VMARegion>& regions)
{
    if (regions.empty()) {
        return 0;
    }
    int32_t successCount = 0;
    std::unordered_set<std::string> successPathNames;
    for (const auto& region : regions) {
        bool success = ApplyMadviseToRegion(region, region.pathname);
        if (success && successPathNames.find(region.pathname) == successPathNames.end()) {
            successCount++;
            successPathNames.insert(region.pathname);
        }
    }
    return successCount;
}

int32_t MadviseGeneralFiles(const std::vector<std::string>& filenames)
{
    if (filenames.empty()) {
        TAG_LOGE(AAFwkTag::ABILITY, "Filename list is empty");
        return 0;
    }
    TAG_LOGD(AAFwkTag::ABILITY, "MadviseGeneralFiles called for %{public}zu files", filenames.size());
    std::vector<AbilityRuntime::VmaUtil::VMARegion> regions = AbilityRuntime::VmaUtil::GetFileVmas(filenames);
    if (regions.empty()) {
        TAG_LOGE(AAFwkTag::ABILITY, "No VMA regions found for any of the %{public}zu files", filenames.size());
        return 0;
    }
    TAG_LOGD(AAFwkTag::ABILITY, "Found %{public}zu total VMA regions", regions.size());
    int32_t successCount = ProcessVmaRegions(regions);
    TAG_LOGD(AAFwkTag::ABILITY, "MadviseGeneralFiles completed: %{public}d segments optimized", successCount);
    return successCount;
}

int32_t MadviseWithConfigFile(const char* bundleName)
{
    if (!bundleName || strlen(bundleName) == 0) {
        TAG_LOGE(AAFwkTag::ABILITY, "Invalid bundle name: null or empty");
        return -1;
    }
    MadviseConfig config = LoadConfigFromFile();
    if (!config.IsValid()) {
        TAG_LOGE(AAFwkTag::ABILITY, "Failed to load valid config");
        return -1;
    }
    return ApplyMadviseWithConfig(bundleName, config);
}

std::string GetConfigPath()
{
    char buf[MAX_PATH_LEN] = { 0 };
    char *configPath = GetOneCfgFile(MADVISE_CONFIG_FILE_PATH, buf, MAX_PATH_LEN);
    if (configPath == nullptr || configPath[0] == '\0' || strlen(configPath) > MAX_PATH_LEN) {
        return MADVISE_CONFIG_DEFAULT_FILE_PATH;
    }
    return configPath;
}
} // namespace MadviseUtil
} // namespace AbilityRuntime
} // namespace OHOS
