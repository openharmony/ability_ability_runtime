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
#include "message_parcel.h"
#include "parcel_macro_base.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {

AppStateFilter::AppStateFilter()
{
}

AppStateFilter::AppStateFilter(FilterCallback callbacks, FilterBundleType bundleTypes, FilterAppStateType appStateTypes,
    FilterProcessStateType processStateTypes, FilterAbilityStateType abilityStateTypes)
    :   callbacks(callbacks),
        bundleTypes(bundleTypes),
        appStateTypes(appStateTypes),
        processStateTypes(processStateTypes),
        abilityStateTypes(abilityStateTypes)
{
}

bool AppStateFilter::ReadFromParcel(Parcel &parcel)
{
    callbacks = static_cast<FilterCallback>(parcel.ReadUint32());
    bundleTypes = static_cast<FilterBundleType>(parcel.ReadUint32());
    appStateTypes = static_cast<FilterAppStateType>(parcel.ReadUint32());
    processStateTypes = static_cast<FilterProcessStateType>(parcel.ReadUint32());
    abilityStateTypes = static_cast<FilterAbilityStateType>(parcel.ReadUint32());
    return true;
}

AppStateFilter *AppStateFilter::Unmarshalling(Parcel &parcel)
{
    AppStateFilter *obj = new (std::nothrow) AppStateFilter();
    if (obj && !obj->ReadFromParcel(parcel)) {
        TAG_LOGW(AAFwkTag::APPMGR, "read from parcel failed");
        delete obj;
        obj = nullptr;
    }
    return obj;
}

bool AppStateFilter::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(static_cast<uint32_t>(callbacks))) {
        TAG_LOGE(AAFwkTag::APPMGR, "write callbacks failed");
        return false;
    }
    if (!parcel.WriteUint32(static_cast<uint32_t>(bundleTypes))) {
        TAG_LOGE(AAFwkTag::APPMGR, "write bundleTypes failed");
        return false;
    }
    if (!parcel.WriteUint32(static_cast<uint32_t>(appStateTypes))) {
        TAG_LOGE(AAFwkTag::APPMGR, "write appStateTypes failed");
        return false;
    }
    if (!parcel.WriteUint32(static_cast<uint32_t>(processStateTypes))) {
        TAG_LOGE(AAFwkTag::APPMGR, "write processStateTypes failed");
        return false;
    }
    if (!parcel.WriteUint32(static_cast<uint32_t>(abilityStateTypes))) {
        TAG_LOGE(AAFwkTag::APPMGR, "write abilityStateTypes failed");
        return false;
    }
    return true;
}

bool AppStateFilter::Match(const AppStateFilter& filter)
{
    if (!(static_cast<uint32_t>(bundleTypes) & static_cast<uint32_t>(filter.bundleTypes)) ||
        !(static_cast<uint32_t>(callbacks) & static_cast<uint32_t>(filter.callbacks))) {
        return false;
    }
    if ((static_cast<uint32_t>(appStateTypes) & static_cast<uint32_t>(filter.appStateTypes)) ||
        (static_cast<uint32_t>(processStateTypes) & static_cast<uint32_t>(filter.processStateTypes)) ||
        (static_cast<uint32_t>(abilityStateTypes) & static_cast<uint32_t>(filter.abilityStateTypes))) {
        return true;
    }
    return false;
}

std::unordered_map<ApplicationState, FilterAppStateType> APPLICATION_STATE_TO_FILTER_MAP = {
    {ApplicationState::APP_STATE_CREATE, FilterAppStateType::CREATE},
    {ApplicationState::APP_STATE_FOREGROUND, FilterAppStateType::FOREGROUND},
    {ApplicationState::APP_STATE_BACKGROUND, FilterAppStateType::BACKGROUND},
    {ApplicationState::APP_STATE_TERMINATED, FilterAppStateType::DESTROY},
    {ApplicationState::APP_STATE_READY, FilterAppStateType::READY},
    {ApplicationState::APP_STATE_FOCUS, FilterAppStateType::FOCUS},
    {ApplicationState::APP_STATE_END, FilterAppStateType::END},
    {ApplicationState::APP_STATE_SET_COLD_START, FilterAppStateType::SET_COLD_START},
    {ApplicationState::APP_STATE_CACHED, FilterAppStateType::CACHED},
    {ApplicationState::APP_STATE_PRE_FOREGROUND, FilterAppStateType::PRE_FOREGROUND},
};

std::unordered_map<AppProcessState, FilterProcessStateType> APP_PROCESS_STATE_TO_FILTER_MAP = {
    {AppProcessState::APP_STATE_CREATE, FilterProcessStateType::CREATE},
    {AppProcessState::APP_STATE_FOREGROUND, FilterProcessStateType::FOREGROUND},
    {AppProcessState::APP_STATE_BACKGROUND, FilterProcessStateType::BACKGROUND},
    {AppProcessState::APP_STATE_TERMINATED, FilterProcessStateType::DESTROY},
    {AppProcessState::APP_STATE_READY, FilterProcessStateType::READY},
    {AppProcessState::APP_STATE_FOCUS, FilterProcessStateType::FOCUS},
    {AppProcessState::APP_STATE_END, FilterProcessStateType::END},
    {AppProcessState::APP_STATE_CACHED, FilterProcessStateType::CACHED},
    {AppProcessState::APP_STATE_PRE_FOREGROUND, FilterProcessStateType::PRE_FOREGROUND},
};

std::unordered_map<AbilityState, FilterAbilityStateType> ABILITY_STATE_TO_FILTER_MAP = {
    {AbilityState::ABILITY_STATE_CREATE, FilterAbilityStateType::CREATE},
    {AbilityState::ABILITY_STATE_FOREGROUND, FilterAbilityStateType::FOREGROUND},
    {AbilityState::ABILITY_STATE_BACKGROUND, FilterAbilityStateType::BACKGROUND},
    {AbilityState::ABILITY_STATE_TERMINATED, FilterAbilityStateType::DESTROY},
    {AbilityState::ABILITY_STATE_READY, FilterAbilityStateType::READY},
    {AbilityState::ABILITY_STATE_FOCUS, FilterAbilityStateType::FOCUS},
    {AbilityState::ABILITY_STATE_END, FilterAbilityStateType::END},
    {AbilityState::ABILITY_STATE_CONNECTED, FilterAbilityStateType::CONNECTED},
    {AbilityState::ABILITY_STATE_DISCONNECTED, FilterAbilityStateType::DISCONNECTED},
};

std::unordered_map<BundleType, FilterBundleType> BUNDLE_TYPE_TO_FILTER_MAP = {
    {BundleType::APP, FilterBundleType::APP},
    {BundleType::ATOMIC_SERVICE, FilterBundleType::ATOMIC_SERVICE},
    {BundleType::SHARED, FilterBundleType::SHARED},
    {BundleType::APP_SERVICE_FWK, FilterBundleType::APP_SERVICE_FWK},
    {BundleType::APP_PLUGIN, FilterBundleType::APP_PLUGIN},
};

FilterAppStateType GetFilterTypeFromApplicationState(ApplicationState state)
{
    auto it = APPLICATION_STATE_TO_FILTER_MAP.find(state);
    if (it != APPLICATION_STATE_TO_FILTER_MAP.end()) {
        return it->second;
    }
    TAG_LOGE(AAFwkTag::APPMGR, "get FilterType from ApplicationState failed");
    return FilterAppStateType::NONE;
}

FilterProcessStateType GetFilterTypeFromAppProcessState(AppProcessState state)
{
    auto it = APP_PROCESS_STATE_TO_FILTER_MAP.find(state);
    if (it != APP_PROCESS_STATE_TO_FILTER_MAP.end()) {
        return it->second;
    }
    TAG_LOGE(AAFwkTag::APPMGR, "get FilterType from AppProcessState failed");
    return FilterProcessStateType::NONE;
}
FilterAbilityStateType GetFilterTypeFromAbilityState(AbilityState state)
{
    auto it = ABILITY_STATE_TO_FILTER_MAP.find(state);
    if (it != ABILITY_STATE_TO_FILTER_MAP.end()) {
        return it->second;
    }
    TAG_LOGE(AAFwkTag::APPMGR, "get FilterType from AbilityState failed");
    return FilterAbilityStateType::NONE;
}
FilterBundleType GetFilterTypeFromBundleType(BundleType state)
{
    auto it = BUNDLE_TYPE_TO_FILTER_MAP.find(state);
    if (it != BUNDLE_TYPE_TO_FILTER_MAP.end()) {
        return it->second;
    }
    TAG_LOGE(AAFwkTag::APPMGR, "get FilterType from BundleType failed");
    return FilterBundleType::NONE;
}
}  // namespace AppExecFwk
}  // namespace OHOS