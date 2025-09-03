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

#ifndef OHOS_ABILITY_RUNTIME_NAPI_COMMON_APP_STATE_FILTER
#define OHOS_ABILITY_RUNTIME_NAPI_COMMON_APP_STATE_FILTER

#include "application_state_filter.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AppExecFwk {
bool UnwrapFilterBundleTypeFromJS(napi_env env, napi_value param, FilterBundleType &filterBundleTypes);
bool UnwrapFilterAppStateTypeFromJS(napi_env env, napi_value param, FilterAppStateType &filterAppStateTypes);
bool UnwrapFilterProcessStateTypeFromJS(napi_env env, napi_value param, FilterProcessStateType &processStateType);
bool UnwrapFilterAbilityStateTypeFromJS(napi_env env, napi_value param, FilterAbilityStateType &abilityStateType);
bool UnwrapFilterCallbackFromJS(napi_env env, napi_value param, FilterCallback &callback);
bool UnwrapAppStateFilterFromJS(napi_env env, napi_value param, AppStateFilter &appStateFilter);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_NAPI_COMMON_APP_STATE_FILTER
