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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_RUNNING_PROCESS_INFO_H
#define MOCK_OHOS_ABILITY_RUNTIME_RUNNING_PROCESS_INFO_H

#include <string>
#include <vector>

#include "ability_info.h"
#include "app_mgr_constants.h"

namespace OHOS {
namespace AppExecFwk {
enum class AppProcessState {
    APP_STATE_CREATE = 0,
    APP_STATE_READY,
    APP_STATE_FOREGROUND,
    APP_STATE_FOCUS,
    APP_STATE_BACKGROUND,
    APP_STATE_TERMINATED,
    APP_STATE_END,
    APP_STATE_CACHED = 100,
};

struct RunningProcessInfo {
    bool isFocused = false;
    bool isTestProcess = false;
    bool isAbilityForegrounding = false;

    bool isDebugApp = false;
    std::int32_t pid_;
    std::int32_t uid_;
    std::int32_t bundleType = 0;
    std::int32_t appCloneIndex = -1;
    std::int32_t rssValue = 0;
    std::int32_t pssValue = 0;
    PreloadMode preloadMode_ = PreloadMode::PRELOAD_NONE;
    AppProcessState state_;
    std::int64_t startTimeMillis_;
    std::vector<std::string> bundleNames;
    std::string processName_;
    std::string instanceKey = "";
    AppExecFwk::MultiAppModeType appMode = AppExecFwk::MultiAppModeType::UNSPECIFIED;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif