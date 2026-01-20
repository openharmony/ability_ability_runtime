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
 * See the License for the specific language governing perns and
 * limitations under the License.
 */

#ifndef OHOS_ABILITY_RUNTIME_ANI_COMMON_APP_STATE_FILTER
#define OHOS_ABILITY_RUNTIME_ANI_COMMON_APP_STATE_FILTER

#include "ani.h"
#include "application_state_filter.h"

namespace OHOS {
namespace AppExecFwk {
bool UnwrapFilterBundleTypeFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterBundleType &bundleType);
bool UnwrapFilterAppStateTypesFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterAppStateType &appStateTypes);
bool UnwrapFilterProcessStateTypeFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterProcessStateType &processStateType);
bool UnwrapFilterAbilityStateTypeFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterAbilityStateType &abilityStateType);
bool UnwrapFilterCallbackFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterCallback &callback);
bool UnWrapAppStateFilter(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::AppStateFilter &appStateFilter);
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_NAPI_COMMON_APP_STATE_FILTER