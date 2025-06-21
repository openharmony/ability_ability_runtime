/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "inner_mission_info.h"

#include "hilog_tag_wrapper.h"
#include "json_utils.h"

namespace OHOS {
namespace AAFwk {
namespace {
const std::string KEY_MISSION_NAME = "MissionName";
const std::string KEY_LAUNCH_MODE = "LaunchMode";
const std::string KEY_MISSION_ID = "MissionId";
const std::string KEY_RUNNING_STATE = "RunningState";
const std::string KEY_LOCKED_STATE = "LockedState";
const std::string KEY_CONTINUABLE = "Continuable";
const std::string KEY_TIME = "Time";
const std::string KEY_LABEL = "Label";
const std::string KEY_ICON_PATH = "IconPath";
const std::string KEY_WANT = "Want";
const std::string KEY_START_METHOD = "StartMethod";
const std::string KEY_BUNDLE_NAME = "BundleName";
const std::string KEY_UID = "Uid";
const std::string KEY_IS_TEMPORARY = "IsTemporary";
const std::string KEY_SPEC_FLAG = "SpecFlag";
const std::string KEY_HAS_RECONER_INFO = "hasRecoverInfo";
}
std::string InnerMissionInfo::ToJsonStr() const
{
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "create json object failed");
        return "";
    }
    cJSON_AddStringToObject(jsonObject, KEY_MISSION_NAME.c_str(), missionName.c_str());
    cJSON_AddNumberToObject(jsonObject, KEY_LAUNCH_MODE.c_str(), static_cast<double>(launchMode));
    cJSON_AddBoolToObject(jsonObject, KEY_IS_TEMPORARY.c_str(), isTemporary);
    cJSON_AddStringToObject(jsonObject, KEY_BUNDLE_NAME.c_str(), bundleName.c_str());
    cJSON_AddNumberToObject(jsonObject, KEY_START_METHOD.c_str(), static_cast<double>(startMethod));
    cJSON_AddNumberToObject(jsonObject, KEY_UID.c_str(), static_cast<double>(uid));
    cJSON_AddStringToObject(jsonObject, KEY_SPEC_FLAG.c_str(), specifiedFlag.c_str());
    cJSON_AddNumberToObject(jsonObject, KEY_MISSION_ID.c_str(), static_cast<double>(missionInfo.id));
    cJSON_AddNumberToObject(jsonObject, KEY_RUNNING_STATE.c_str(), static_cast<double>(missionInfo.runningState));
    cJSON_AddBoolToObject(jsonObject, KEY_LOCKED_STATE.c_str(), missionInfo.lockedState);
    cJSON_AddBoolToObject(jsonObject, KEY_CONTINUABLE.c_str(), missionInfo.continuable);
    cJSON_AddStringToObject(jsonObject, KEY_TIME.c_str(), missionInfo.time.c_str());
    cJSON_AddStringToObject(jsonObject, KEY_LABEL.c_str(), missionInfo.label.c_str());
    cJSON_AddStringToObject(jsonObject, KEY_ICON_PATH.c_str(), missionInfo.iconPath.c_str());
    cJSON_AddStringToObject(jsonObject, KEY_WANT.c_str(), missionInfo.want.ToUri().c_str());
    cJSON_AddBoolToObject(jsonObject, KEY_HAS_RECONER_INFO.c_str(), hasRecoverInfo);

    std::string jsonStr = AAFwk::JsonUtils::GetInstance().ToString(jsonObject);
    cJSON_Delete(jsonObject);
    return jsonStr;
}

bool InnerMissionInfo::FromJsonStr(const std::string &jsonStr)
{
    if (jsonStr.empty()) {
        return false;
    }

    cJSON *value = cJSON_Parse(jsonStr.c_str());
    if (value == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "json failed: %{private}s", jsonStr.c_str());
        return false;
    }

    cJSON *missionNameItem = cJSON_GetObjectItem(value, KEY_MISSION_NAME.c_str());
    cJSON *launchModeItem = cJSON_GetObjectItem(value, KEY_LAUNCH_MODE.c_str());
    cJSON *isTemporaryItem = cJSON_GetObjectItem(value, KEY_IS_TEMPORARY.c_str());
    cJSON *startMethodItem = cJSON_GetObjectItem(value, KEY_START_METHOD.c_str());
    cJSON *bundleNameItem = cJSON_GetObjectItem(value, KEY_BUNDLE_NAME.c_str());
    cJSON *uidItem = cJSON_GetObjectItem(value, KEY_UID.c_str());
    cJSON *specifiedFlagItem = cJSON_GetObjectItem(value, KEY_SPEC_FLAG.c_str());
    cJSON *missionIdItem = cJSON_GetObjectItem(value, KEY_MISSION_ID.c_str());
    cJSON *runningStateItem = cJSON_GetObjectItem(value, KEY_RUNNING_STATE.c_str());
    cJSON *lockedStateItem = cJSON_GetObjectItem(value, KEY_LOCKED_STATE.c_str());
    cJSON *continuableItem = cJSON_GetObjectItem(value, KEY_CONTINUABLE.c_str());
    cJSON *timeItem = cJSON_GetObjectItem(value, KEY_TIME.c_str());
    cJSON *labelItem = cJSON_GetObjectItem(value, KEY_LABEL.c_str());
    cJSON *iconPathItem = cJSON_GetObjectItem(value, KEY_ICON_PATH.c_str());
    cJSON *hasRecoverInfoItem = cJSON_GetObjectItem(value, KEY_HAS_RECONER_INFO.c_str());
    cJSON *wantItem = cJSON_GetObjectItem(value, KEY_WANT.c_str());
    if (!CheckJsonValue(missionNameItem, JsonType::STRING) || !CheckJsonValue(launchModeItem, JsonType::NUMBER) ||
        !CheckJsonValue(isTemporaryItem, JsonType::BOOLEAN) || !CheckJsonValue(startMethodItem, JsonType::NUMBER) ||
        !CheckJsonValue(bundleNameItem, JsonType::STRING) || !CheckJsonValue(uidItem, JsonType::NUMBER) ||
        !CheckJsonValue(specifiedFlagItem, JsonType::STRING) || !CheckJsonValue(missionIdItem, JsonType::NUMBER) ||
        !CheckJsonValue(runningStateItem, JsonType::NUMBER) || !CheckJsonValue(lockedStateItem, JsonType::BOOLEAN) ||
        !CheckJsonValue(continuableItem, JsonType::BOOLEAN) || !CheckJsonValue(timeItem, JsonType::STRING) ||
        !CheckJsonValue(labelItem, JsonType::STRING) || !CheckJsonValue(iconPathItem, JsonType::STRING) ||
        !CheckJsonValue(hasRecoverInfoItem, JsonType::BOOLEAN) || !CheckJsonValue(wantItem, JsonType::STRING)) {
        cJSON_Delete(value);
        return false;
    }
    missionName = missionNameItem->valuestring;
    launchMode = static_cast<int32_t>(launchModeItem->valuedouble);
    isTemporary = isTemporaryItem->type == cJSON_True;
    startMethod = static_cast<int32_t>(startMethodItem->valuedouble);
    bundleName = bundleNameItem->valuestring;
    uid = static_cast<int32_t>(uidItem->valuedouble);
    specifiedFlag = specifiedFlagItem->valuestring;
    missionInfo.id = static_cast<int32_t>(missionIdItem->valuedouble);
    missionInfo.runningState = static_cast<int32_t>(runningStateItem->valuedouble);
    missionInfo.lockedState = lockedStateItem->type == cJSON_True;
    missionInfo.continuable = continuableItem->type == cJSON_True;
    missionInfo.time = timeItem->valuestring;
    missionInfo.label = labelItem->valuestring;
    missionInfo.iconPath = iconPathItem->valuestring;
    hasRecoverInfo = hasRecoverInfoItem->type == cJSON_True;
    std::string wantStr = wantItem->valuestring;

    Want* want = Want::ParseUri(wantStr);
    if (want) {
        missionInfo.want = *want;
    }

    cJSON_Delete(value);
    return true;
}

void InnerMissionInfo::Dump(std::vector<std::string> &info) const
{
    std::string dumpInfo = "      Mission ID #" + std::to_string(missionInfo.id);
    info.push_back(dumpInfo);
    dumpInfo = "        mission name [" + missionName + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        runningState [" + std::to_string(missionInfo.runningState) + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        lockedState [" + std::to_string(missionInfo.lockedState) + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        continuable [" + std::to_string(missionInfo.continuable) + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        timeStamp [" + missionInfo.time + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        label [" + missionInfo.label + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        iconPath [" + missionInfo.iconPath + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        want [" + missionInfo.want.ToUri() + "]";
    info.push_back(dumpInfo);
}

bool InnerMissionInfo::CheckJsonValue(cJSON *value, JsonType jsonType)
{
    if (value == nullptr) {
        return false;
    }
    if (jsonType == JsonType::NUMBER) {
        return cJSON_IsNumber(value);
    } else if (jsonType == JsonType::STRING) {
        return cJSON_IsString(value);
    } else if (jsonType == JsonType::BOOLEAN) {
        return cJSON_IsBool(value);
    }
    return false;
}

bool InnerMissionInfo::CheckJsonNode(cJSON *value, const std::string &node, JsonType jsonType)
{
    cJSON *item = cJSON_GetObjectItem(value, node.c_str());
    if (item == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "node %{private}s null", node.c_str());
        return false;
    }

    if (jsonType == JsonType::NUMBER) {
        return cJSON_IsNumber(item);
    }
    if (jsonType == JsonType::STRING) {
        return cJSON_IsString(item);
    }
    if (jsonType == JsonType::BOOLEAN) {
        return cJSON_IsBool(item);
    }
    return false;
}
}  // namespace AAFwk
}  // namespace OHOS
