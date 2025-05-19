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

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <vector>
#include "application_configuration_manager.h"
#include "configuration_utils.h"
#include "unicode/locid.h"

namespace OHOS {
namespace AbilityRuntime {

bool operator<(SetLevel lhs, SetLevel rhs)
{
    return static_cast<uint8_t>(lhs) < static_cast<uint8_t>(rhs);
};

bool operator>(SetLevel lhs, SetLevel rhs)
{
    return static_cast<uint8_t>(lhs) > static_cast<uint8_t>(rhs);
};

ApplicationConfigurationManager& ApplicationConfigurationManager::GetInstance()
{
    static ApplicationConfigurationManager instance;
    return instance;
}

void ApplicationConfigurationManager::SetLanguageSetLevel(SetLevel languageSetLevel)
{
    languageSetLevel_ = languageSetLevel;
}

SetLevel ApplicationConfigurationManager::GetLanguageSetLevel() const
{
    return languageSetLevel_;
}

void ApplicationConfigurationManager::SetfontSetLevel(SetLevel fontSetLevel)
{
    fontSetLevel_ = fontSetLevel;
}

SetLevel ApplicationConfigurationManager::GetFontSetLevel() const
{
    return fontSetLevel_;
}

std::string ApplicationConfigurationManager::SetColorModeSetLevel(SetLevel colorModeSetLevel, const std::string &value)
{
    colorModeVal_[static_cast<uint8_t>(colorModeSetLevel)] = value;
    for (int i = static_cast<uint8_t>(SetLevel::SetLevelCount) - 1; i >= 0; i--) {
        if (!colorModeVal_[i].empty() &&
            colorModeVal_[i].compare(AppExecFwk::ConfigurationInner::COLOR_MODE_AUTO) != 0) {
            colorModeSetLevel_ = static_cast<SetLevel>(i);
            break;
        }
    }

    return colorModeVal_[static_cast<uint8_t>(colorModeSetLevel_)];
}

std::string ApplicationConfigurationManager::GetColorMode()
{
    for (int i = static_cast<uint8_t>(SetLevel::SetLevelCount) - 1; i >= 0; i--) {
        if (!colorModeVal_[i].empty() &&
            colorModeVal_[i].compare(AppExecFwk::ConfigurationInner::COLOR_MODE_AUTO) != 0) {
            colorModeSetLevel_ = static_cast<SetLevel>(i);
            break;
        }
    }

    return colorModeVal_[static_cast<uint8_t>(colorModeSetLevel_)];
}

SetLevel ApplicationConfigurationManager::GetColorModeSetLevel() const
{
    return colorModeSetLevel_;
}

bool ApplicationConfigurationManager::ColorModeHasSetByApplication() const
{
    return !colorModeVal_[static_cast<uint8_t>(SetLevel::Application)].empty();
}

void ApplicationConfigurationManager::AddIgnoreContext(
    std::shared_ptr<Context> context, std::shared_ptr<Global::Resource::ResourceManager> resourceManager)
{
    ignoreContext_.insert(std::make_pair(context, resourceManager));
}

void ApplicationConfigurationManager::DeleteIgnoreContext(std::shared_ptr<Context> context)
{
    ignoreContext_.erase(context);
}

std::vector<std::shared_ptr<Context>> ApplicationConfigurationManager::GetIgnoreContext()
{
    std::vector<std::shared_ptr<Context>> keys;
    std::transform(ignoreContext_.begin(), ignoreContext_.end(), std::back_inserter(keys),
        [](const auto& pair) {
            return pair.first;
        });
    return keys;
}

std::vector<std::shared_ptr<Global::Resource::ResourceManager>> ApplicationConfigurationManager::GetIgnoreResource()
{
    std::vector<std::shared_ptr<Global::Resource::ResourceManager>> values;
    std::transform(ignoreContext_.begin(), ignoreContext_.end(), std::back_inserter(values),
        [](const auto& pair) {
            return pair.second;
        });
    return values;
}

std::string ApplicationConfigurationManager::GetUpdatedLocale(const std::string& systemLocale,
    const std::string& systemLanguage)
{
    if (systemLocale.empty() || systemLanguage.empty()) {
        return "";
    }

    UErrorCode status = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(systemLocale.c_str(), status);
    if (U_FAILURE(status)) {
        return "";
    }

    icu::Locale language = icu::Locale::forLanguageTag(systemLanguage.c_str(), status);
    if (U_FAILURE(status)) {
        return "";
    }

    std::string extendParamTag;
    size_t pos = systemLocale.find("-u-");
    if (pos != std::string::npos) {
        extendParamTag = systemLocale.substr(pos);
    }

    std::string languageTag = language.getLanguage();
    std::string scriptTag = language.getScript();
    std::string regionTag = locale.getCountry();

    std::string effectiveLocale = languageTag;
    std::string splitor = "-";
    if (!scriptTag.empty()) {
        effectiveLocale += splitor + scriptTag;
    }
    if (!regionTag.empty()) {
        effectiveLocale += splitor + regionTag;
    }
    if (!extendParamTag.empty()) {
        effectiveLocale += extendParamTag;
    }
    return effectiveLocale;
}
} // namespace AbilityRuntime
} // namespace OHOS