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

#include "ets_mission_info_utils.h"

#include "ani.h"
#include "ani_common_want.h"
#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"
#include "mission_info.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {

namespace {
constexpr const char* ETS_MISSION_INFO_NAME = "Lapplication/MissionInfo/MissionInfoInner;";
constexpr const char* KEY_MISSION_ID = "missionId";
constexpr const char* KEY_RUNNING_STATE = "runningState";
constexpr const char* KEY_LOCKED_STATE = "lockedState";
constexpr const char* KEY_TIMESTAMP = "timestamp";
constexpr const char* KEY_LABEL = "label";
constexpr const char* KEY_ICON_PATH = "iconPath";
constexpr const char* KEY_CONTINUABLE = "continuable";
constexpr const char* KEY_ABILITY_STATE = "abilityState";
constexpr const char* KEY_UNCLEARABLE = "unclearable";
constexpr const char* KEY_WANT = "want";
constexpr const char *WANT_CLASS_NAME = "@ohos.app.ability.Want.Want";
constexpr const char *SET_OBJECT_VOID_SIGNATURE = "ILstd/core/Object;:V";
}

bool InnerCreateEtsWantParams(ani_env *env, ani_class wantCls, ani_object wantObject,
    const AAFwk::WantParams &wantParams)
{
    ani_ref wantParamRef = AppExecFwk::WrapWantParams(env, wantParams);
    if (wantParamRef == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "failed to WrapWantParams");
        return false;
    }
    return AppExecFwk::SetFieldRefByName(env, wantCls, wantObject, "parameters", wantParamRef);
}

ani_object CreateEtsWant(ani_env *env, const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::MISSION, "WrapWant called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "null env");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if ((status = env->FindClass(WANT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "status: %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "null wantCls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "status: %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "null object");
        return nullptr;
    }

    auto elementName = want.GetElement();
    AppExecFwk::SetFieldStringByName(env, cls, object, "deviceId", elementName.GetDeviceID());
    AppExecFwk::SetFieldStringByName(env, cls, object, "bundleName", elementName.GetBundleName());
    AppExecFwk::SetFieldStringByName(env, cls, object, "abilityName", elementName.GetAbilityName());
    AppExecFwk::SetFieldStringByName(env, cls, object, "uri", want.GetUriString());
    AppExecFwk::SetFieldStringByName(env, cls, object, "type", want.GetType());
    AppExecFwk::SetFieldIntByName(env, cls, object, "flags", want.GetFlags());
    AppExecFwk::SetFieldStringByName(env, cls, object, "action", want.GetAction());
    InnerCreateEtsWantParams(env, cls, object, want.GetParams());
    AppExecFwk::SetFieldArrayStringByName(env, cls, object, "entities", want.GetEntities());

    return object;
}

bool WrapWantInner(ani_env *env, ani_class cls, ani_object object, const AAFwk::Want &want)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "env is null");
        return false;
    }
    ani_object wantObj = CreateEtsWant(env, want);
    if (wantObj == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "wrap want failed");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_field wantField = nullptr;
    status = env->Class_FindField(cls, KEY_WANT, &wantField);
    if (status != ANI_OK || wantField == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "find want field failed status: %{public}d, or wantField is nullptr", status);
        return false;
    }
    status = env->Object_SetField_Ref(object, wantField, reinterpret_cast<ani_ref>(wantObj));
    if (status != ANI_OK || wantObj == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "Object_SetField_Ref failed status: %{public}d, or wantObj is unllptr", status);
        return false;
    }
    return true;
}

bool WrapMissionInfo(ani_env *env, ani_class cls, ani_object object, const AAFwk::MissionInfo &missionInfo)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "result or env is null");
        return false;
    }
    if (!AppExecFwk::SetIntPropertyValue(env, object, KEY_MISSION_ID, missionInfo.id) ||
        !AppExecFwk::SetIntPropertyValue(env, object, KEY_RUNNING_STATE, missionInfo.runningState) ||
        !AppExecFwk::SetFieldBoolByName(env, cls, object, KEY_LOCKED_STATE, missionInfo.lockedState) ||
        !AppExecFwk::SetFieldStringByName(env, cls, object, KEY_TIMESTAMP, missionInfo.time) ||
        !AppExecFwk::SetFieldStringByName(env, cls, object, KEY_LABEL, missionInfo.label) ||
        !AppExecFwk::SetFieldStringByName(env, cls, object, KEY_ICON_PATH, missionInfo.iconPath) ||
        !AppExecFwk::SetFieldBoolByName(env, cls, object, KEY_CONTINUABLE, missionInfo.continuable) ||
        !AppExecFwk::SetIntPropertyValue(env, object, KEY_ABILITY_STATE, missionInfo.abilityState) ||
        !AppExecFwk::SetFieldBoolByName(env, cls, object, KEY_UNCLEARABLE, missionInfo.unclearable)) {
            TAG_LOGE(AAFwkTag::MISSION, "set mission info failed");
            return false;
        }

    if (!WrapWantInner(env, cls, object, missionInfo.want)) {
        TAG_LOGE(AAFwkTag::MISSION, "wrap want failed");
        return false;
    }
    return true;
}

ani_object CreateEtsMissionInfo(ani_env *env, const AAFwk::MissionInfo &missionInfo)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "result or env is null");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    status = env->FindClass(ETS_MISSION_INFO_NAME, &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "find MissionInfo failed status: %{public}d, or cls is nullptr", status);
        return nullptr;
    }
    ani_method method = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "Class_FindMethod ctor failed status: %{public}d, method cls is nullptr", status);
        return nullptr;
    }
    ani_object object = nullptr;
    status = env->Object_New(cls, method, &object);
    if (status != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "Object_New failed status: %{public}d, or object is nullptr", status);
        return nullptr;
    }

    if (!WrapMissionInfo(env, cls, object, missionInfo)) {
        TAG_LOGE(AAFwkTag::MISSION, "WrapMissionInfo failed");
        return nullptr;
    }
    return object;
}

ani_object CreateEtsMissionInfos(ani_env *env, const std::vector<AAFwk::MissionInfo> &missionInfos)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "env is null");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    ani_status status = ANI_ERROR;
    status = env->FindClass("Lescompat/Array;", &arrayCls);
    if (status != ANI_OK || arrayCls == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "FindClass failed, status : %{public}d", status);
        return nullptr;
    }

    ani_method arrayCtor = nullptr;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor);
    if (status != ANI_OK || arrayCtor == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "Class_FindMethod failed, status : %{public}d", status);
        return nullptr;
    }

    ani_object arrayObj = nullptr;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, missionInfos.size());
    if (status != ANI_OK || arrayObj == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "Object_New failed, status : %{public}d", status);
        return arrayObj;
    }

    ani_size index = 0;
    for (auto &missionInfo : missionInfos) {
        ani_object object = CreateEtsMissionInfo(env, missionInfo);
        if (object == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "CreateEtsMissionInfo failed");
            return nullptr;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", SET_OBJECT_VOID_SIGNATURE, index, object);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::MISSION, "Object_CallMethodByName_Void failed, status : %{public}d", status);
            return nullptr;
        }
        index++;
    }
    return arrayObj;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
