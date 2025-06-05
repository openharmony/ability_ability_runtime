/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 *
 */

#include "cj_utils_ffi.h"

#include "securec.h"
#include "hilog_tag_wrapper.h"
#include "cj_macro.h"

char* CreateCStringFromString(const std::string& source)
{
    if (source.size() == 0) {
        return nullptr;
    }
    size_t length = source.size() + 1;
    auto res = static_cast<char*>(malloc(length));
    if (res == nullptr) {
        TAG_LOGE(AAFwkTag::DEFAULT, "null res");
        return nullptr;
    }
    if (strcpy_s(res, length, source.c_str()) != 0) {
        free(res);
        TAG_LOGE(AAFwkTag::DEFAULT, "Strcpy failed");
        return nullptr;
    }
    return res;
}

char** VectorToCArrString(const std::vector<std::string>& vec)
{
    if (vec.size() == 0) {
        return nullptr;
    }
    char** result = static_cast<char**>(malloc(sizeof(char*) * vec.size()));
    if (result == nullptr) {
        return nullptr;
    }
    for (size_t i = 0; i < vec.size(); i++) {
        result[i] = CreateCStringFromString(vec[i]);
    }
    return result;
}

int32_t ConvertColorMode(std::string colormode)
{
    auto resolution = -1;
    static const std::vector<std::pair<std::string, int32_t>> resolutions = {
        { "dark", 0 },
        { "light", 1 },
    };
    for (const auto& [tempColorMode, value] : resolutions) {
        if (tempColorMode == colormode) {
            resolution = value;
            break;
        }
    }
    return resolution;
}

int32_t ConvertDirection(std::string direction)
{
    auto resolution = -1;
    static const std::vector<std::pair<std::string, int32_t>> resolutions = {
        { "vertical", 0 },
        { "horizontal", 1 },
    };
    for (const auto& [tempDirection, value] : resolutions) {
        if (tempDirection == direction) {
            resolution = value;
            break;
        }
    }
    return resolution;
}

int32_t ConvertDensity(std::string density)
{
    auto resolution = 0;
    static const std::vector<std::pair<std::string, int32_t>> resolutions = {
        { "sdpi", 120 },
        { "mdpi", 160 },
        { "ldpi", 240 },
        { "xldpi", 320 },
        { "xxldpi", 480 },
        { "xxxldpi", 640 },
    };
    for (const auto& [tempdensity, value] : resolutions) {
        if (tempdensity == density) {
            resolution = value;
            break;
        }
    }
    return resolution;
}

int32_t ConvertDisplayId(std::string displayId)
{
    if (displayId == OHOS::AppExecFwk::ConfigurationInner::EMPTY_STRING) {
        return -1;
    }
    return std::stoi(displayId);
}

namespace OHOS {
namespace AbilityRuntime {

CConfiguration CreateCConfiguration(const OHOS::AppExecFwk::Configuration &configuration)
{
    CConfiguration cfg;
    cfg.language = CreateCStringFromString(configuration.GetItem(
        OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE));
    cfg.colorMode = ConvertColorMode(configuration.GetItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE));
    std::string direction = configuration.GetItem(OHOS::AppExecFwk::ConfigurationInner::APPLICATION_DIRECTION);
    cfg.direction = ConvertDirection(direction);
    std::string density = configuration.GetItem(OHOS::AppExecFwk::ConfigurationInner::APPLICATION_DENSITYDPI);
    cfg.screenDensity = ConvertDensity(density);
    cfg.displayId = ConvertDisplayId(configuration.GetItem(
        OHOS::AppExecFwk::ConfigurationInner::APPLICATION_DISPLAYID));
    std::string hasPointerDevice = configuration.GetItem(OHOS::AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
    cfg.hasPointerDevice = hasPointerDevice == "true" ? true : false;
    std::string fontSizeScale = configuration.GetItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
    cfg.fontSizeScale = fontSizeScale == "" ? 1.0 : std::stod(fontSizeScale);
    std::string fontWeightScale = configuration.GetItem(
        OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE);
    cfg.fontWeightScale = fontWeightScale == "" ? 1.0 : std::stod(fontWeightScale);
    cfg.mcc = CreateCStringFromString(configuration.GetItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_MCC));
    cfg.mnc = CreateCStringFromString(configuration.GetItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_MNC));
    return cfg;
}

void FreeCConfiguration(CConfiguration configuration)
{
    free(configuration.language);
    free(configuration.mcc);
    free(configuration.mnc);
}

extern "C" {
CJ_EXPORT CConfiguration OHOS_ConvertConfiguration(void* param)
{
    CConfiguration cCfg = {};
    auto config = reinterpret_cast<AppExecFwk::Configuration*>(param);
    if (config == nullptr) {
        return cCfg;
    }
    return CreateCConfiguration(*config);
}
}
}
}