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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_START_WITH_WAIT_OBSERVER_UTIL_H
#define OHOS_ABILITY_RUNTIME_ABILITY_START_WITH_WAIT_OBSERVER_UTIL_H

namespace OHOS {
namespace AAFwk {
namespace AbilityStartWithWaitObserverUtil {
enum class TerminateReason {
    TERMINATE_FOR_NONE = 0,
    TERMINATE_FOR_NON_UI_ABILITY,
    TERMINATE_FOR_UI_ABILITY_FOREGROUND_FAILED,
};
}  // namespace AbilityStartWithWaitObserverUtil
}  // namespace AAFwk
}  // namespace OHOS
 
#endif  // OHOS_ABILITY_RUNTIME_ABILITY_START_WITH_WAIT_OBSERVER_UTIL_H
 