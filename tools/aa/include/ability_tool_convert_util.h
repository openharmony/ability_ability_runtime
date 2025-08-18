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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_TOOL_CONVERT_UTIL_H
#define OHOS_ABILITY_RUNTIME_ABILITY_TOOL_CONVERT_UTIL_H

#include <string>

#include "ability_state.h"

namespace OHOS {
namespace AAFwk {
namespace AbilityToolConvertUtil {
static Reason CovertExitReason(const std::string& reasonStr)
{
    if (reasonStr.empty()) {
        return Reason::REASON_UNKNOWN;
    }

    if (reasonStr.compare("UNKNOWN") == 0) {
        return Reason::REASON_UNKNOWN;
    }

    if (reasonStr.compare("NORMAL") == 0) {
        return Reason::REASON_NORMAL;
    }

    if (reasonStr.compare("CPP_CRASH") == 0) {
        return Reason::REASON_CPP_CRASH;
    }

    if (reasonStr.compare("JS_ERROR") == 0) {
        return Reason::REASON_JS_ERROR;
    }

    if (reasonStr.compare("ABILITY_NOT_RESPONDING") == 0) {
        return Reason::REASON_APP_FREEZE;
    }

    if (reasonStr.compare("APP_FREEZE") == 0) {
        return Reason::REASON_APP_FREEZE;
    }

    if (reasonStr.compare("PERFORMANCE_CONTROL") == 0) {
        return Reason::REASON_PERFORMANCE_CONTROL;
    }

    if (reasonStr.compare("RESOURCE_CONTROL") == 0) {
        return Reason::REASON_RESOURCE_CONTROL;
    }

    if (reasonStr.compare("UPGRADE") == 0) {
        return Reason::REASON_UPGRADE;
    }

    return Reason::REASON_UNKNOWN;
}
}  // namespace AbilityUtil
}  // namespace AAFwk
}  // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ABILITY_TOOL_CONVERT_UTIL_H
