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

#include "ani_common_app_state_filter.h"

#include "ani_common_util.h"
#include "application_state_filter.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
bool UnwrapFilterBundleTypeFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterBundleType &bundleType)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null env");
        return false;
    }

    ani_ref obj = nullptr;
    ani_status status = ANI_ERROR;
    if (!AppExecFwk::GetRefProperty(env, etsAppStateFilter, "bundleTypes", obj)) {
        return true;
    }

    ani_int mid = 0;
    status = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(obj), "intValue", nullptr, &mid);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return false;
    }
    uint32_t allBundleTypes = static_cast<uint32_t>(AppExecFwk::FilterBundleType::APP) |
        static_cast<uint32_t>(AppExecFwk::FilterBundleType::ATOMIC_SERVICE);
    if (static_cast<uint32_t>(mid) & (~allBundleTypes)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Invalid filterBundleTypes value: %{public}u", mid);
        return false;
    }
    bundleType = static_cast<AppExecFwk::FilterBundleType>(mid);
    return true;
}

bool UnwrapFilterAppStateTypesFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterAppStateType &appStateTypes)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null env");
        return false;
    }

    ani_ref obj = nullptr;
    ani_status status = ANI_ERROR;
    if (!AppExecFwk::GetRefProperty(env, etsAppStateFilter, "appStateTypes", obj)) {
        return true;
    }

    ani_int mid = 0;
    status = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(obj), "intValue", nullptr, &mid);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return false;
    }
    uint32_t allAppStateTypes = static_cast<uint32_t>(AppExecFwk::FilterAppStateType::CREATE) |
        static_cast<uint32_t>(AppExecFwk::FilterAppStateType::FOREGROUND) |
        static_cast<uint32_t>(AppExecFwk::FilterAppStateType::BACKGROUND) |
        static_cast<uint32_t>(AppExecFwk::FilterAppStateType::DESTROY);
    if (static_cast<uint32_t>(mid) & (~allAppStateTypes)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Invalid filterAppStateTypes value: %{public}u", mid);
        return false;
    }
    appStateTypes = static_cast<AppExecFwk::FilterAppStateType>(mid);
    return true;
}

bool UnwrapFilterProcessStateTypeFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterProcessStateType &processStateType)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null env");
        return false;
    }
    ani_ref obj = nullptr;
    ani_status status = ANI_ERROR;
    if (!AppExecFwk::GetRefProperty(env, etsAppStateFilter, "processStateTypes", obj)) {
        return true;
    }

    ani_int mid = 0;
    status = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(obj), "intValue", nullptr, &mid);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return false;
    }
    uint32_t allProcessStateTypes = static_cast<uint32_t>(AppExecFwk::FilterProcessStateType::CREATE) |
        static_cast<uint32_t>(AppExecFwk::FilterProcessStateType::FOREGROUND) |
        static_cast<uint32_t>(AppExecFwk::FilterProcessStateType::BACKGROUND) |
        static_cast<uint32_t>(AppExecFwk::FilterProcessStateType::DESTROY);
    if (static_cast<uint32_t>(mid) & (~allProcessStateTypes)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Invalid processStateType value: %{public}u", mid);
        return false;
    }
    processStateType = static_cast<AppExecFwk::FilterProcessStateType>(mid);
    return true;
}

bool UnwrapFilterAbilityStateTypeFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterAbilityStateType &abilityStateType)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null env");
        return false;
    }

    ani_ref obj = nullptr;
    ani_status status = ANI_ERROR;
    if (!AppExecFwk::GetRefProperty(env, etsAppStateFilter, "abilityStateTypes", obj)) {
        return true;
    }

    ani_int mid = 0;
    status = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(obj), "intValue", nullptr, &mid);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return false;
    }
    uint32_t allAbilityStateTypes = static_cast<uint32_t>(AppExecFwk::FilterAbilityStateType::CREATE) |
        static_cast<uint32_t>(AppExecFwk::FilterAbilityStateType::FOREGROUND) |
        static_cast<uint32_t>(AppExecFwk::FilterAbilityStateType::BACKGROUND) |
        static_cast<uint32_t>(AppExecFwk::FilterAbilityStateType::DESTROY);
    if (static_cast<uint32_t>(mid) & (~allAbilityStateTypes)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Invalid abilityStateTypes value: %{public}u", mid);
        return false;
    }
    abilityStateType = static_cast<AppExecFwk::FilterAbilityStateType>(mid);
    return true;
}

bool UnwrapFilterCallbackFromEts(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::FilterCallback &callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null env");
        return false;
    }

    ani_ref obj = nullptr;
    ani_status status = ANI_ERROR;
    if (!AppExecFwk::GetRefProperty(env, etsAppStateFilter, "callbacks", obj)) {
        callback = static_cast<AppExecFwk::FilterCallback>(
            static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_FOREGROUND_APPLICATION_CHANGED) |
            static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_ABILITY_STATE_CHANGED) |
            static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_PROCESS_CREATED) |
            static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_PROCESS_DIED) |
            static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_PROCESS_STATE_CHANGED) |
            static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_APP_STARTED) |
            static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_APP_STOPPED) |
            static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_EXTENSION_STATE_CHANGED)
        );
        return true;
    }

    ani_int mid = 0;
    status = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(obj), "intValue", nullptr, &mid);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return false;
    }
    uint32_t uintCallbacks = static_cast<uint32_t>(mid);
    uint32_t allCallbacks = static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_FOREGROUND_APPLICATION_CHANGED) |
        static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_ABILITY_STATE_CHANGED) |
        static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_PROCESS_CREATED) |
        static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_PROCESS_DIED) |
        static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_PROCESS_STATE_CHANGED) |
        static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_APP_STARTED) |
        static_cast<uint32_t>(AppExecFwk::FilterCallback::ON_APP_STOPPED);
    if (uintCallbacks & (~allCallbacks)) {
        TAG_LOGE(AAFwkTag::APPMGR, "Invalid allCallback value: %{public}u", mid);
        return false;
    }
    if (uintCallbacks & static_cast<uint32_t>(FilterCallback::ON_ABILITY_STATE_CHANGED)) {
        uintCallbacks |= static_cast<uint32_t>(FilterCallback::ON_EXTENSION_STATE_CHANGED);
    }
    callback = static_cast<AppExecFwk::FilterCallback>(uintCallbacks);
    return true;
}

bool UnWrapAppStateFilter(ani_env *env,
    const ani_object &etsAppStateFilter, OHOS::AppExecFwk::AppStateFilter &appStateFilter)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env is null");
        return false;
    }
    if (!UnwrapFilterBundleTypeFromEts(env, etsAppStateFilter, appStateFilter.bundleTypes)) {
        TAG_LOGE(AAFwkTag::APPMGR, "get bundleTypes failed");
        return false;
    }
    if (!UnwrapFilterAppStateTypesFromEts(env, etsAppStateFilter, appStateFilter.appStateTypes)) {
        TAG_LOGE(AAFwkTag::APPMGR, "get appStateTypes failed");
        return false;
    }
    if (!UnwrapFilterProcessStateTypeFromEts(env, etsAppStateFilter, appStateFilter.processStateTypes)) {
        TAG_LOGE(AAFwkTag::APPMGR, "get processStateTypes failed");
        return false;
    }
    if (!UnwrapFilterAbilityStateTypeFromEts(env, etsAppStateFilter, appStateFilter.abilityStateTypes)) {
        TAG_LOGE(AAFwkTag::APPMGR, "get abilityStateTypes failed");
        return false;
    }
    if (!UnwrapFilterCallbackFromEts(env, etsAppStateFilter, appStateFilter.callbacks)) {
        TAG_LOGE(AAFwkTag::APPMGR, "get callbacks failed");
        return false;
    }
    return true;
}
} //AppExecFwk
} //OHOS