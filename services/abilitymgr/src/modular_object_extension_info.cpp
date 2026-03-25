/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "modular_object_extension_info.h"
#include "nlohmann/json.hpp"
#include "json_util.h"

namespace {
constexpr const char *JSON_KEY_BUNDLE_NAME = "bundleName";
constexpr const char *JSON_KEY_MODULE_NAME = "moduleName";
constexpr const char *JSON_KEY_ABILITY_NAME = "abilityName";
constexpr const char *JSON_KEY_APP_INDEX = "appIndex";
constexpr const char *JSON_KEY_LAUNCH_MODE = "launchMode";
constexpr const char *JSON_KEY_PROCESS_MODE = "processMode";
constexpr const char *JSON_KEY_THREAD_MODE = "threadMode";
constexpr const char *JSON_KEY_IS_DISABLED = "isDisabled";
}
namespace OHOS {
namespace AAFwk {
bool ModularObjectExtensionInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = parcel.ReadString();
    moduleName = parcel.ReadString();
    abilityName = parcel.ReadString();
    appIndex = parcel.ReadInt32();
    launchMode = static_cast<MoeLaunchMode>(parcel.ReadInt32());
    processMode = static_cast<MoeProcessMode>(parcel.ReadInt32());
    threadMode = static_cast<MoeThreadMode>(parcel.ReadInt32());
    isDisabled = parcel.ReadBool();
    return true;
}

bool ModularObjectExtensionInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(bundleName)) {
        return false;
    }
    if (!parcel.WriteString(moduleName)) {
        return false;
    }
    if (!parcel.WriteString(abilityName)) {
        return false;
    }
    if (!parcel.WriteInt32(appIndex)) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(launchMode))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(processMode))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(threadMode))) {
        return false;
    }
    if (!parcel.WriteBool(isDisabled)) {
        return false;
    }
    return true;
}

ModularObjectExtensionInfo *ModularObjectExtensionInfo::Unmarshalling(Parcel &parcel)
{
    ModularObjectExtensionInfo *info = new (std::nothrow) ModularObjectExtensionInfo();
    if (info == nullptr) {
        return nullptr;
    }
    if (!info->ReadFromParcel(parcel)) {
        delete info;
        return nullptr;
    }
    return info;
}

std::string ModularObjectExtensionInfo::ToJsonString() const
{
    nlohmann::json jsonObject = nlohmann::json {
        {JSON_KEY_BUNDLE_NAME, bundleName},
        {JSON_KEY_MODULE_NAME, moduleName},
        {JSON_KEY_ABILITY_NAME, abilityName},
        {JSON_KEY_APP_INDEX, appIndex},
        {JSON_KEY_LAUNCH_MODE, static_cast<int32_t>(launchMode)},
        {JSON_KEY_PROCESS_MODE, static_cast<int32_t>(processMode)},
        {JSON_KEY_THREAD_MODE, static_cast<int32_t>(threadMode)},
        {JSON_KEY_IS_DISABLED, isDisabled},
    };
    return jsonObject.dump();
}

bool ModularObjectExtensionInfo::FromJsonString(const std::string &jsonString)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonString, nullptr, false);
    if (jsonObject.is_discarded() || !jsonObject.is_object()) {
        return false;
    }

    int32_t parseResult = ERR_OK;
    const auto &jsonObjectEnd = jsonObject.end();
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(
        jsonObject, jsonObjectEnd, JSON_KEY_BUNDLE_NAME, bundleName, false, parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(
        jsonObject, jsonObjectEnd, JSON_KEY_MODULE_NAME, moduleName, false, parseResult);
    AppExecFwk::BMSJsonUtil::GetStrValueIfFindKey(
        jsonObject, jsonObjectEnd, JSON_KEY_ABILITY_NAME, abilityName, false, parseResult);
    AppExecFwk::GetValueIfFindKey<int32_t>(
        jsonObject, jsonObjectEnd, JSON_KEY_APP_INDEX, appIndex, AppExecFwk::JsonType::NUMBER,
        false, parseResult, AppExecFwk::ArrayType::NOT_ARRAY);
    AppExecFwk::BMSJsonUtil::GetBoolValueIfFindKey(
        jsonObject, jsonObjectEnd, JSON_KEY_IS_DISABLED, isDisabled, false, parseResult);

    int32_t enumValue = 0;
    AppExecFwk::GetValueIfFindKey<int32_t>(
        jsonObject, jsonObjectEnd, JSON_KEY_LAUNCH_MODE, enumValue, AppExecFwk::JsonType::NUMBER,
        false, parseResult, AppExecFwk::ArrayType::NOT_ARRAY);
    launchMode = static_cast<MoeLaunchMode>(enumValue);
    AppExecFwk::GetValueIfFindKey<int32_t>(
        jsonObject, jsonObjectEnd, JSON_KEY_PROCESS_MODE, enumValue, AppExecFwk::JsonType::NUMBER,
        false, parseResult, AppExecFwk::ArrayType::NOT_ARRAY);
    processMode = static_cast<MoeProcessMode>(enumValue);
    AppExecFwk::GetValueIfFindKey<int32_t>(
        jsonObject, jsonObjectEnd, JSON_KEY_THREAD_MODE, enumValue, AppExecFwk::JsonType::NUMBER,
        false, parseResult, AppExecFwk::ArrayType::NOT_ARRAY);
    threadMode = static_cast<MoeThreadMode>(enumValue);

    if (parseResult != ERR_OK) {
        return false;
    }
    return true;
}
} // namespace AAFwk
} // namespace OHOS
