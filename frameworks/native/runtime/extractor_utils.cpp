/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "extractor_utils.h"

#include <regex>

#include "ability_constants.h"
#include "hilog_wrapper.h"
#include "runtime_extractor.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
inline bool StringStartWith(const std::string& str, const char* startStr, size_t startStrLen)
{
    return ((str.length() >= startStrLen) && (str.compare(0, startStrLen, startStr) == 0));
}
} // namespace

std::shared_ptr<RuntimeExtractor> InitRuntimeExtractor(const std::string& hapPath)
{
    if (hapPath.empty()) {
        HILOG_ERROR("InitRuntimeExtractor::hapPath is nullptr");
        return nullptr;
    }

    std::string loadPath;
    if (!StringStartWith(hapPath, Constants::SYSTEM_APP_PATH, sizeof(Constants::SYSTEM_APP_PATH) - 1)) {
        std::regex hapPattern(std::string(Constants::ABS_CODE_PATH) + std::string(Constants::FILE_SEPARATOR));
        loadPath = std::regex_replace(hapPath, hapPattern, "");
        loadPath = std::string(Constants::LOCAL_CODE_PATH) + std::string(Constants::FILE_SEPARATOR) +
            loadPath.substr(loadPath.find(std::string(Constants::FILE_SEPARATOR)) + 1);
    } else {
        loadPath = hapPath;
    }
    auto runtimeExtractor = std::make_shared<RuntimeExtractor>(loadPath, hapPath);
    if (!runtimeExtractor->Init()) {
        HILOG_ERROR("InitRuntimeExtractor::Runtime extractor init failed");
        return nullptr;
    }

    return runtimeExtractor;
}

bool GetFileBuffer(
    const std::shared_ptr<RuntimeExtractor>& runtimeExtractor, const std::string& srcPath, std::ostringstream &dest)
{
    if (runtimeExtractor == nullptr || srcPath.empty()) {
        HILOG_ERROR("GetFileBuffer::runtimeExtractor or srcPath is nullptr");
        return false;
    }

    std::regex srcPattern(std::string(Constants::LOCAL_CODE_PATH) + std::string(Constants::FILE_SEPARATOR));
    std::string relativePath = std::regex_replace(srcPath, srcPattern, "");
    relativePath = relativePath.substr(relativePath.find(std::string(Constants::FILE_SEPARATOR)) + 1);
    if (!runtimeExtractor->ExtractByName(relativePath, dest)) {
        HILOG_ERROR("GetFileBuffer::Extract file failed");
        return false;
    }

    return true;
}

bool GetFileBufferFromHap(const std::string& hapPath, const std::string& srcPath, std::ostringstream &dest)
{
    if (hapPath.empty() || srcPath.empty()) {
        HILOG_ERROR("GetFileBufferFromHap::hapPath or srcPath is nullptr");
        return false;
    }

    return GetFileBuffer(InitRuntimeExtractor(hapPath), srcPath, dest);
}

bool GetFileListFromHap(const std::string& hapPath, const std::string& srcPath, std::vector<std::string>& assetList)
{
    if (hapPath.empty() || srcPath.empty()) {
        HILOG_ERROR("GetFileListFromHap::hapPath or srcPath is nullptr");
        return false;
    }

    std::string loadPath;
    if (!StringStartWith(hapPath, Constants::SYSTEM_APP_PATH, sizeof(Constants::SYSTEM_APP_PATH) - 1)) {
        std::regex hapPattern(std::string(Constants::ABS_CODE_PATH) + std::string(Constants::FILE_SEPARATOR));
        loadPath = std::regex_replace(hapPath, hapPattern, "");
        loadPath = std::string(Constants::LOCAL_CODE_PATH) + std::string(Constants::FILE_SEPARATOR) +
            loadPath.substr(loadPath.find(std::string(Constants::FILE_SEPARATOR)) + 1);
    } else {
        loadPath = hapPath;
    }
    RuntimeExtractor runtimeExtractor(loadPath);
    if (!runtimeExtractor.Init()) {
        HILOG_ERROR("GetFileListFromHap::Runtime extractor init failed");
        return false;
    }

    std::regex srcPattern(std::string(Constants::LOCAL_CODE_PATH) + std::string(Constants::FILE_SEPARATOR));
    std::string relativePath = std::regex_replace(srcPath, srcPattern, "");
    relativePath = relativePath.substr(relativePath.find(std::string(Constants::FILE_SEPARATOR)) + 1);

    std::vector<std::string> fileList;
    if (!runtimeExtractor.GetZipFileNames(fileList)) {
        HILOG_ERROR("GetFileListFromHap::Get file list failed");
        return false;
    }

    std::regex replacePattern(relativePath);
    for (auto value : fileList) {
        if (StringStartWith(value, relativePath.c_str(), sizeof(relativePath.c_str()) - 1)) {
            std::string realpath = std::regex_replace(value, replacePattern, "");
            if (realpath.find(Constants::FILE_SEPARATOR) != std::string::npos) {
                continue;
            }
            assetList.emplace_back(value);
        }
    }

    return true;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
