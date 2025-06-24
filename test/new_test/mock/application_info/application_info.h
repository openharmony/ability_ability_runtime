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

#ifndef MOCK_FOUNDATION_ABILITY_RUNTIME_SIMULATOR_COMMON_APPLICATION_INFO_H
#define MOCK_FOUNDATION_ABILITY_RUNTIME_SIMULATOR_COMMON_APPLICATION_INFO_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
enum class MultiAppModeType : uint8_t {
    UNSPECIFIED = 0,
    MULTI_INSTANCE = 1,
    APP_CLONE = 2,
};

enum class BundleType {
    APP = 0,
    ATOMIC_SERVICE = 1,
    SHARED = 2,
};

struct Metadata {
    std::string name;
    std::string value;
    std::string resource;
};

struct CustomizeData {
    std::string name;
    std::string value;
    std::string extra;
};

struct MetaData {
    std::vector<CustomizeData> customizeData;
};

struct Resource {
    std::string bundleName;
    std::string moduleName;
    int32_t id = 0;
};

struct ApplicationInfo {
    std::string name;
    std::string bundleName;
    uint32_t versionCode = 0;
    std::string versionName;
    int32_t minCompatibleVersionCode = 0;
    uint32_t apiCompatibleVersion = 0;
    int32_t apiTargetVersion = 0;
    std::string iconPath;
    int32_t iconId = 0;
    Resource iconResource;
    std::string label;
    int32_t labelId = 0;
    Resource labelResource;
    int32_t flags = 0;
    BundleType bundleType = BundleType::APP;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif