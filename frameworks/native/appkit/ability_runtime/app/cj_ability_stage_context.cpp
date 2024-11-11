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
 */

#include "cj_ability_stage_context.h"
#include "ffi_remote_data.h"
#include "hap_module_info.h"
#include "ability_runtime/context/context.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char* res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "MallocCString malloc failed");
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

static Global::Resource::ColorMode ConvertColorMode(const std::string& colormode)
{
    auto resolution = Global::Resource::ColorMode::COLOR_MODE_NOT_SET;

    static const std::vector<std::pair<std::string, Global::Resource::ColorMode>> resolutions = {
        { "dark", Global::Resource::ColorMode::DARK },
        { "light", Global::Resource::ColorMode::LIGHT },
    };

    for (const auto& [tempColorMode, value] : resolutions) {
        if (tempColorMode == colormode) {
            resolution = value;
            break;
        }
    }

    return resolution;
}

static Global::Resource::Direction ConvertDirection(const std::string& direction)
{
    auto resolution = Global::Resource::Direction::DIRECTION_NOT_SET;

    static const std::vector<std::pair<std::string, Global::Resource::Direction>> resolutions = {
        { "vertical", Global::Resource::Direction::DIRECTION_VERTICAL },
        { "horizontal", Global::Resource::Direction::DIRECTION_HORIZONTAL },
    };

    for (const auto& [tempDirection, value] : resolutions) {
        if (tempDirection == direction) {
            resolution = value;
            break;
        }
    }

    return resolution;
}

static Global::Resource::ScreenDensity ConvertDensity(const std::string& density)
{
    auto resolution = Global::Resource::ScreenDensity::SCREEN_DENSITY_NOT_SET;

    static const std::vector<std::pair<std::string, Global::Resource::ScreenDensity>> resolutions = {
        { "sdpi", Global::Resource::ScreenDensity::SCREEN_DENSITY_SDPI },
        { "mdpi", Global::Resource::ScreenDensity::SCREEN_DENSITY_MDPI },
        { "ldpi", Global::Resource::ScreenDensity::SCREEN_DENSITY_LDPI },
        { "xldpi", Global::Resource::ScreenDensity::SCREEN_DENSITY_XLDPI },
        { "xxldpi", Global::Resource::ScreenDensity::SCREEN_DENSITY_XXLDPI },
        { "xxxldpi", Global::Resource::ScreenDensity::SCREEN_DENSITY_XXXLDPI },
    };

    for (const auto& [tempdensity, value] : resolutions) {
        if (tempdensity == density) {
            resolution = value;
            break;
        }
    }

    return resolution;
}

static int32_t ConvertDisplayId(const std::string& displayId)
{
    if (displayId == AppExecFwk::ConfigurationInner::EMPTY_STRING) {
        return -1;
    }

    return std::stoi(displayId);
}

CConfiguration ConvertConfiguration(const AppExecFwk::Configuration &configuration)
{
    CConfiguration cfg;
    cfg.language = MallocCString(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE));
    cfg.colorMode = ConvertColorMode(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE));
    std::string direction = configuration.GetItem(AppExecFwk::ConfigurationInner::APPLICATION_DIRECTION);
    cfg.direction = ConvertDirection(direction);
    std::string density = configuration.GetItem(AppExecFwk::ConfigurationInner::APPLICATION_DENSITYDPI);
    cfg.screenDensity = ConvertDensity(density);
    cfg.displayId = ConvertDisplayId(configuration.GetItem(AppExecFwk::ConfigurationInner::APPLICATION_DISPLAYID));
    std::string hasPointerDevice = configuration.GetItem(AAFwk::GlobalConfigurationKey::INPUT_POINTER_DEVICE);
    cfg.hasPointerDevice = hasPointerDevice == "true" ? true : false;
    std::string fontSizeScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
    cfg.fontSizeScale = fontSizeScale == "" ? 1.0 : std::stod(fontSizeScale);
    std::string fontWeightScale = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_WEIGHT_SCALE);
    cfg.fontWeightScale = fontWeightScale == "" ? 1.0 : std::stod(fontWeightScale);
    cfg.mcc = MallocCString(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MCC));
    cfg.mnc = MallocCString(configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_MNC));
    return cfg;
}

RetHapModuleInfo CJAbilityStageContext::GetRetHapModuleInfo()
{
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null, getHapModuleInfo failed. ");
        return RetHapModuleInfo();
    }

    auto hapInfo = context->GetHapModuleInfo();
    if (hapInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "CurrentHapMoudleInfo is nullptr.");
        return RetHapModuleInfo();
    }

    return OHOS::CJSystemapi::BundleManager::Convert::ConvertHapModuleInfo(*hapInfo);
}

std::shared_ptr<AppExecFwk::HapModuleInfo> CJAbilityStageContext::GetHapModuleInfo()
{
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null, getHapModuleInfo failed. ");
        return nullptr;
    }
    return context->GetHapModuleInfo();
}

CConfiguration CJAbilityStageContext::GetConfiguration()
{
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null, getConfiguration failed. ");
        return CConfiguration();
    }

    auto configuration = context->GetConfiguration();
    if (configuration == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "CurrentConfiguration is nullptr.");
        return CConfiguration();
    }

    return ConvertConfiguration(*configuration);
}

}
}