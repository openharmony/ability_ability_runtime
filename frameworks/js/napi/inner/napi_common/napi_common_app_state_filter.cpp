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

#include "application_state_filter.h"
#include "hilog_tag_wrapper.h"
#include "napi_common_app_state_filter.h"
#include "napi_common_util.h"

namespace OHOS {
namespace AppExecFwk {
bool UnwrapFilterBundleTypeFromJS(napi_env env, napi_value param, FilterBundleType &filterBundleTypes)
{
    uint32_t bundleTypes = 0;
    if (IsExistsByPropertyName(env, param, "bundleTypes")) {
        if (!UnwrapUint32ByPropertyName(env, param, "bundleTypes", bundleTypes)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Unwrap filterBundleTypes failed");
            return false;
        }
        uint32_t allBundleTypes = static_cast<uint32_t>(FilterBundleType::APP) |
            static_cast<uint32_t>(FilterBundleType::ATOMIC_SERVICE);
        if (bundleTypes & (~allBundleTypes)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Invalid filterBundleTypes value: %{public}u", bundleTypes);
            return false;
        }
        filterBundleTypes = static_cast<FilterBundleType>(bundleTypes);
    }
    return true;
}

bool UnwrapFilterAppStateTypeFromJS(napi_env env, napi_value param, FilterAppStateType &filterAppStateTypes)
{
    uint32_t appStateTypes = 0;
    if (IsExistsByPropertyName(env, param, "appStateTypes")) {
        if (!UnwrapUint32ByPropertyName(env, param, "appStateTypes", appStateTypes)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Unwrap filterAppStateTypes failed");
            return false;
        }
        uint32_t allAppStateTypes = static_cast<uint32_t>(FilterAppStateType::CREATE) |
            static_cast<uint32_t>(FilterAppStateType::FOREGROUND) |
            static_cast<uint32_t>(FilterAppStateType::BACKGROUND) |
            static_cast<uint32_t>(FilterAppStateType::DESTROY);
        if (appStateTypes & (~allAppStateTypes)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Invalid filterAppStateTypes value: %{public}u",  appStateTypes);
            return false;
        }
        filterAppStateTypes = static_cast<FilterAppStateType>(appStateTypes);
    }
    return true;
}

bool UnwrapFilterProcessStateTypeFromJS(napi_env env, napi_value param, FilterProcessStateType &filterProcessStateTypes)
{
    uint32_t processStateTypes = 0;
    if (IsExistsByPropertyName(env, param, "processStateTypes")) {
        if (!UnwrapUint32ByPropertyName(env, param, "processStateTypes", processStateTypes)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Unwrap filterProcessStateTypes failed");
            return false;
        }
        uint32_t allProcessStateTypes = static_cast<uint32_t>(FilterProcessStateType::CREATE) |
            static_cast<uint32_t>(FilterProcessStateType::FOREGROUND) |
            static_cast<uint32_t>(FilterProcessStateType::BACKGROUND) |
            static_cast<uint32_t>(FilterProcessStateType::DESTROY);
        if (processStateTypes & (~allProcessStateTypes)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Invalid filterProcessStateTypes value: %{public}u",  processStateTypes);
            return false;
        }
        filterProcessStateTypes = static_cast<FilterProcessStateType>(processStateTypes);
    }
    return true;
}

bool UnwrapFilterAbilityStateTypeFromJS(napi_env env, napi_value param, FilterAbilityStateType &filterAbilityStateType)
{
    uint32_t abilityStateTypes = 0;
    if (IsExistsByPropertyName(env, param, "abilityStateTypes")) {
        if (!UnwrapUint32ByPropertyName(env, param, "abilityStateTypes", abilityStateTypes)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Unwrap filterAbilityStateTypes failed");
            return false;
        }
        uint32_t allAbilityStateTypes = static_cast<uint32_t>(FilterAbilityStateType::CREATE) |
            static_cast<uint32_t>(FilterAbilityStateType::FOREGROUND) |
            static_cast<uint32_t>(FilterAbilityStateType::BACKGROUND) |
            static_cast<uint32_t>(FilterAbilityStateType::DESTROY);
        if (abilityStateTypes & (~allAbilityStateTypes)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Invalid filterAbilityStateTypes value: %{public}u",  abilityStateTypes);
            return false;
        }
        filterAbilityStateType = static_cast<FilterAbilityStateType>(abilityStateTypes);
    }
    return true;
}

bool UnwrapFilterCallbackFromJS(napi_env env, napi_value param, FilterCallback &filterCallback)
{
    uint32_t callbacks = 0;
    if (IsExistsByPropertyName(env, param, "callbacks")) {
        if (!UnwrapUint32ByPropertyName(env, param, "callbacks", callbacks)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Unwrap filterCallbacks failed");
            return false;
        }
        uint32_t allCallbacks = static_cast<uint32_t>(FilterCallback::ON_FOREGROUND_APPLICATION_CHANGED) |
            static_cast<uint32_t>(FilterCallback::ON_ABILITY_STATE_CHANGED) |
            static_cast<uint32_t>(FilterCallback::ON_PROCESS_CREATED) |
            static_cast<uint32_t>(FilterCallback::ON_PROCESS_DIED) |
            static_cast<uint32_t>(FilterCallback::ON_PROCESS_STATE_CHANGED) |
            static_cast<uint32_t>(FilterCallback::ON_APP_STARTED) |
            static_cast<uint32_t>(FilterCallback::ON_APP_STOPPED);
        if (callbacks & (~allCallbacks)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Invalid filterCallbacks value: %{public}u",  callbacks);
            return false;
        }
        if (callbacks & static_cast<uint32_t>(FilterCallback::ON_ABILITY_STATE_CHANGED)) {
            callbacks |= static_cast<uint32_t>(FilterCallback::ON_EXTENSION_STATE_CHANGED);
        }
        filterCallback = static_cast<FilterCallback>(callbacks);
    } else {
        filterCallback = static_cast<FilterCallback>(
            static_cast<uint32_t>(FilterCallback::ON_FOREGROUND_APPLICATION_CHANGED) |
            static_cast<uint32_t>(FilterCallback::ON_ABILITY_STATE_CHANGED) |
            static_cast<uint32_t>(FilterCallback::ON_PROCESS_CREATED) |
            static_cast<uint32_t>(FilterCallback::ON_PROCESS_DIED) |
            static_cast<uint32_t>(FilterCallback::ON_PROCESS_STATE_CHANGED) |
            static_cast<uint32_t>(FilterCallback::ON_APP_STARTED) |
            static_cast<uint32_t>(FilterCallback::ON_APP_STOPPED) |
            static_cast<uint32_t>(FilterCallback::ON_EXTENSION_STATE_CHANGED)
        );
    }
    return true;
}

bool UnwrapAppStateFilterFromJS(napi_env env, napi_value param, AppStateFilter &appStateFilter)
{
    if (UnwrapFilterBundleTypeFromJS(env, param, appStateFilter.bundleTypes) &&
        UnwrapFilterAppStateTypeFromJS(env, param, appStateFilter.appStateTypes) &&
        UnwrapFilterProcessStateTypeFromJS(env, param, appStateFilter.processStateTypes) &&
        UnwrapFilterAbilityStateTypeFromJS(env, param, appStateFilter.abilityStateTypes) &&
        UnwrapFilterCallbackFromJS(env, param, appStateFilter.callbacks)) {
            return true;
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
