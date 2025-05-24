/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "accessibility_ability_command.h"
#include "accessibility_config.h"

namespace{
const int32_t TYPE_NORMAL = 0;
const int32_t TYPE_PROTANOMALY = 1;
const int32_t TYPE_DEUTERANOMALY = 2;
const int32_t TYPE_TRITANOMALY = 3;
}

namespace OHOS {
namespace AAFwk {
Accessibility::RetError MockSetScreenMagnificationState() {
    AccessibilityCommandArgument argument;
    argument.command = "setScreenMagnificationState";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    bool state = std::atoi(argument.value.c_str()) == 1;
    return config.SetScreenMagnificationState(state);
}

Accessibility::RetError MockRunAsSetShortkeyState() {
    AccessibilityCommandArgument argument;
    argument.command = "setShortKeyState";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    bool state = std::atoi(argument.value.c_str()) == 1;
    return config.SetShortKeyState(state);
}

Accessibility::RetError MockRunAsSetMouseKeyState() {
    AccessibilityCommandArgument argument;
    argument.command = "setMouseKeyState";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    bool state = std::atoi(argument.value.c_str()) == 1;
    return config.SetMouseKeyState(state);
}

Accessibility::RetError MockRunAsSetCaptionState() {
    AccessibilityCommandArgument argument;
    argument.command = "setCaptionState";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    bool state = std::atoi(argument.value.c_str()) == 1;
    return config.SetCaptionsState(state);
}

Accessibility::RetError MockRunAsSetMouseAutoClick() {
    AccessibilityCommandArgument argument;
    argument.command = "setMouseAutoClick";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    float time = 1.0 * std::atoi(argument.value.c_str()) / 100;
    return config.SetMouseAutoClick(time);
}

Accessibility::RetError MockRunAsSetHighContrastTextState() {
    AccessibilityCommandArgument argument;
    argument.command = "setHighContrastTextState";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    bool state = std::atoi(argument.value.c_str()) == 1;
    return config.SetHighContrastTextState(state);
}

Accessibility::RetError MockRunAsSetInvertColorState() {
    AccessibilityCommandArgument argument;
    argument.command = "setInvertColorState";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    bool state = std::atoi(argument.value.c_str()) == 1;
    return config.SetInvertColorState(state);
}

Accessibility::RetError MockRunAsSetDaltonizationColorFilter() {
    AccessibilityCommandArgument argument;
    argument.command = "setDaltonizationColorFilter";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    int32_t value = std::atoi(argument.value.c_str());
    AccessibilityConfig::DALTONIZATION_TYPE type = AccessibilityConfig::DALTONIZATION_TYPE::Normal;
    switch (value) {
        case TYPE_NORMAL: {
            type = AccessibilityConfig::DALTONIZATION_TYPE::Normal;
            break;
        }
        case TYPE_PROTANOMALY: {
            type = AccessibilityConfig::DALTONIZATION_TYPE::Protanomaly;
            break;
        }
        case TYPE_DEUTERANOMALY: {
            type = AccessibilityConfig::DALTONIZATION_TYPE::Deuteranomaly;
            break;
        }
        case TYPE_TRITANOMALY: {
            type = AccessibilityConfig::DALTONIZATION_TYPE::Tritanomaly;
            break;
        }
        default: {
            break;
        }
    }
    return config.SetDaltonizationColorFilter(type);
}

Accessibility::RetError MockRunAsSetContentTimeout() {
    AccessibilityCommandArgument argument;
    argument.command = "setContentTimeout";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    int32_t time = std::atoi(argument.value.c_str());
    return config.SetContentTimeout(time);
}

Accessibility::RetError MockRunAsSetAnimationOffState() {
    AccessibilityCommandArgument argument;
    argument.command = "setAnimationOffState";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    bool state = std::atoi(argument.value.c_str()) == 1;
    return config.SetAnimationOffState(state);
}

Accessibility::RetError MockRunAsSetAudioMonoState() {
    AccessibilityCommandArgument argument;
    argument.command = "setAudioMonoState";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    bool state = std::atoi(argument.value.c_str()) == 1;
    return config.SetAudioMonoState(state);
}

Accessibility::RetError MockRunAsSetAudioBalance() {
    AccessibilityCommandArgument argument;
    argument.command = "setAudioBalance";
    auto& config = OHOS::AccessibilityConfig::AccessibilityConfig::GetInstance();
    (void)config.InitializeContext();
    float balance = 1.0 * std::atoi(argument.value.c_str()) / 100;
    return config.SetAudioBalance(balance);
}
}  // namespace AAFwk
}  // namespace OHOS