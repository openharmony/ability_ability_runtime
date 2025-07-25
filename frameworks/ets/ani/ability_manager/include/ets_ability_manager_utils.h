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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_MANAGER_UTILS_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_MANAGER_UTILS_H

#include "ability_running_info.h"
#include "ability_state_data.h"
#include "ani.h"
#include "extension_running_info.h"

namespace OHOS {
namespace AbilityManagerEts {
using OHOS::AppExecFwk::AbilityStateData;
ani_object WrapAbilityStateData(ani_env *env, const AbilityStateData &abilityStateData);
bool SetAbilityStateData(ani_env *env, ani_object object, const AbilityStateData &abilityStateData);
bool WrapAbilityRunningInfo(ani_env *env, ani_object &infoObj, const AAFwk::AbilityRunningInfo &info);
bool WrapAbilityRunningInfoArray(
    ani_env *env, ani_object &arrayObj, const std::vector<AAFwk::AbilityRunningInfo> &infos);
bool WrapAbilityRunningInfoInner(
    ani_env *env, ani_object &infoObj, const AAFwk::AbilityRunningInfo &info, ani_class cls);
bool WrapExtensionRunningInfo(ani_env *env, ani_object &infoObj, const AAFwk::ExtensionRunningInfo &info);
bool WrapExtensionRunningInfoInner(
    ani_env *env, ani_object &infoObj, const AAFwk::ExtensionRunningInfo &info, ani_class cls);
bool WrapArrayString(ani_env *env, ani_object &arrayObj, const std::vector<std::string> &values);
} // namespace AbilityManagerEts
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_ABILITY_MANAGER_UTILS_H
