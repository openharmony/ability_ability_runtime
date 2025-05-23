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

#ifndef OHOS_APPLICATION_CONFIGURATION_MANAGER_H
#define OHOS_APPLICATION_CONFIGURATION_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "context.h"
#include "resource_manager.h"

namespace OHOS {
namespace AbilityRuntime {
enum class SetLevel : uint8_t {
    // system level, only color mode have SA level
    System,
    SA,
    // application level
    Application,
    SetLevelCount,
};

class ApplicationConfigurationManager {
    ApplicationConfigurationManager() = default;
    ~ApplicationConfigurationManager() = default;
public:
    static ApplicationConfigurationManager& GetInstance();
    void SetLanguageSetLevel(SetLevel languageSetLevel);
    void SetfontSetLevel(SetLevel fontSetLevel);
    SetLevel GetLanguageSetLevel() const;
    SetLevel GetFontSetLevel() const;
    std::string SetColorModeSetLevel(SetLevel colorModeSetLevel, const std::string &value);
    SetLevel GetColorModeSetLevel() const;
    std::string GetColorMode();
    bool ColorModeHasSetByApplication() const;
    void AddIgnoreContext(std::shared_ptr<Context> context,
        std::shared_ptr<Global::Resource::ResourceManager> resourceManager);
    void DeleteIgnoreContext(std::shared_ptr<Context> context);
    std::vector<std::shared_ptr<Context>> GetIgnoreContext();
    std::vector<std::shared_ptr<Global::Resource::ResourceManager>> GetIgnoreResource();
    static std::string GetUpdatedLocale(const std::string& systemLocale, const std::string& systemLanguage);

private:
    SetLevel languageSetLevel_ = SetLevel::System;
    SetLevel colorModeSetLevel_ = SetLevel::System;
    SetLevel fontSetLevel_ = SetLevel::System;
    std::vector<std::string> colorModeVal_ =
        std::vector<std::string>(static_cast<uint8_t>(SetLevel::SetLevelCount));
    std::map<std::shared_ptr<Context>, std::shared_ptr<Global::Resource::ResourceManager>> ignoreContext_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif