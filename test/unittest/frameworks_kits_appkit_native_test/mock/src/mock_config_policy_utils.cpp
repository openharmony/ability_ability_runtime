/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <climits>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <gtest/gtest.h>

#include "config_policy_utils.h"
#include "mock_config_policy_utils.h"
#include "securec.h"

namespace OHOS {
namespace AbilityRuntime {
MockConfigPolicyUtils& MockConfigPolicyUtils::GetInstance()
{
    static MockConfigPolicyUtils instance;
    return instance;
}

MockConfigPolicyUtils::~MockConfigPolicyUtils()
{
    std::error_code ec;
    if (std::filesystem::exists(oneCfgFilePath_, ec) &&
        std::filesystem::is_regular_file(oneCfgFilePath_, ec) &&
        std::filesystem::remove(oneCfgFilePath_, ec)) {
        GTEST_LOG_(INFO) << "SetOneCfgFilePath remove " << oneCfgFilePath_;
        oneCfgFilePath_.clear();
    }
}

const char* MockConfigPolicyUtils::GetOneCfgFilePath()
{
    return oneCfgFilePathIsNull_ ? nullptr : oneCfgFilePath_.c_str();
}

void MockConfigPolicyUtils::SetOneCfgFilePathIsNull()
{
    std::error_code ec;
    if (std::filesystem::exists(oneCfgFilePath_, ec) &&
        std::filesystem::is_regular_file(oneCfgFilePath_, ec) &&
        std::filesystem::remove(oneCfgFilePath_, ec)) {
        GTEST_LOG_(INFO) << "SetOneCfgFilePath remove " << oneCfgFilePath_;
    }
    oneCfgFilePath_.clear();
    oneCfgFilePathIsNull_ = true;
}

void MockConfigPolicyUtils::SetOneCfgFilePath(std::string fileName, bool isCreate, bool isRoot)
{
    std::error_code ec;
    if (std::filesystem::exists(oneCfgFilePath_, ec) &&
        std::filesystem::is_regular_file(oneCfgFilePath_, ec) &&
        std::filesystem::remove(oneCfgFilePath_, ec)) {
        GTEST_LOG_(INFO) << "SetOneCfgFilePath remove " << oneCfgFilePath_;
    }

    oneCfgFilePathIsNull_ = false;
    if (fileName.empty()) {
        oneCfgFilePath_ = fileName;
        GTEST_LOG_(INFO) << "SetOneCfgFilePath fileName is empty";
        return;
    }

    oneCfgFilePath_.clear();
    if (isRoot) {
        oneCfgFilePath_.append("/").append(fileName);
    } else {
        std::filesystem::path currentDir = std::filesystem::current_path(ec);
        oneCfgFilePath_.append(currentDir).append("/").append(fileName);
    }

    if (isCreate) {
        std::ofstream file(oneCfgFilePath_);
        GTEST_LOG_(INFO) << "SetOneCfgFilePath create file [" << oneCfgFilePath_ << "] is " <<
            (file.is_open() ? "success" : "failure");
    }
}

bool MockConfigPolicyUtils::GetRealPathStatus()
{
    return realPathIsNull_;
}

void MockConfigPolicyUtils::SetRealPathIsNull(bool isNull)
{
    realPathIsNull_ = isNull;
}
}
}