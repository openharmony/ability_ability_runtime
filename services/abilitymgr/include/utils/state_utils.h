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

#ifndef OHOS_ABILITY_RUNTIME_STATE_UTILS_H
#define OHOS_ABILITY_RUNTIME_STATE_UTILS_H

#include <string>

#include "ability_state.h"
#include "app_scheduler.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class StateUtils
 * provides state utilities.
 */
class StateUtils final {
public:
    /**
     * StateToStrMap, convert ability state to string.
     *
     * @param state The ability state.
     * @return The string ability state.
     */
    static std::string StateToStrMap(const AbilityState &state);

    /**
     * AppStateToStrMap, convert app state to string.
     *
     * @param state The app state.
     * @return The string app state.
     */
    static std::string AppStateToStrMap(const AppState &state);

    /**
     * ConvertStateMap, convert ability lifecycle state to string.
     *
     * @param state The ability lifecycle state.
     * @return The string ability lifecycle state.
     */
    static int ConvertStateMap(const AbilityLifeCycleState &state);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif //OHOS_ABILITY_RUNTIME_STATE_UTILS_H
