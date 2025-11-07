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

#include "ets_data_struct_converter.h"

#include "ani_enum_convert.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *CLASSNAME_LAUNCHPARAM = "@ohos.app.ability.AbilityConstant.LaunchParamImpl";
constexpr const char *CLASSNAME_LAUNCHREASON = "@ohos.app.ability.AbilityConstant.AbilityConstant.LaunchReason";
constexpr const char *CLASSNAME_LAST_EXITREASION = "@ohos.app.ability.AbilityConstant.AbilityConstant.LastExitReason";
constexpr const char *LAST_EXIT_DETAIL_INFO_IMPL_CLASS_NAME =
    "@ohos.app.ability.AbilityConstant.LastExitDetailInfoImpl";
constexpr const char *ENUMNAME_PROCESS = "@ohos.app.ability.appManager.appManager.ProcessState";
ani_string GetAniString(ani_env *env, const std::string &str)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null env");
        return nullptr;
    }
    ani_string aniStr = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to getAniString, status: %{public}d", status);
        return nullptr;
    }
    return aniStr;
}

ani_object CreateEtsLastExitDetailInfo(ani_env* env, const AAFwk::LastExitDetailInfo& lastExitDetailInfo)
{
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(LAST_EXIT_DETAIL_INFO_IMPL_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "status: %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null cls");
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "status: %{public}d", status);
        return nullptr;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null method");
        return nullptr;
    }
    ani_object object = nullptr;
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "status: %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null object");
        return nullptr;
    }
    env->Object_SetPropertyByName_Int(object, "pid", lastExitDetailInfo.pid);
    env->Object_SetPropertyByName_Ref(object, "processName", GetAniString(env, lastExitDetailInfo.processName));
    env->Object_SetPropertyByName_Int(object, "uid", lastExitDetailInfo.uid);
    env->Object_SetPropertyByName_Int(object, "exitSubReason", lastExitDetailInfo.exitSubReason);
    env->Object_SetPropertyByName_Ref(object, "exitMsg", GetAniString(env, lastExitDetailInfo.exitMsg));
    env->Object_SetPropertyByName_Int(object, "rss", lastExitDetailInfo.rss);
    env->Object_SetPropertyByName_Int(object, "pss", lastExitDetailInfo.pss);
    env->Object_SetPropertyByName_Long(object, "timestamp", lastExitDetailInfo.timestamp);
    
    ani_enum_item stateItem {};
    AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env,
        ENUMNAME_PROCESS, lastExitDetailInfo.processState, stateItem);
    if ((status = env->Object_SetPropertyByName_Ref(object, "processState", stateItem)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::BRIDGE, "processState failed status:%{public}d", status);
        return nullptr;
    }
    return object;
}

bool WrapLaunchParamInner(ani_env *env, const AAFwk::LaunchParam &launchParam, ani_object &object)
{
    ani_status status = ANI_ERROR;
    ani_enum_item launchReasonItem = nullptr;
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(
        env, CLASSNAME_LAUNCHREASON, launchParam.launchReason, launchReasonItem);
    if ((status = env->Object_SetPropertyByName_Ref(object, "launchReason", launchReasonItem)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to set launchReason");
        return false;
    }

    ani_enum_item lastExitReasonItem = nullptr;
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(
        env, CLASSNAME_LAST_EXITREASION, launchParam.lastExitReason, lastExitReasonItem);
    if ((status = env->Object_SetPropertyByName_Ref(object, "lastExitReason", lastExitReasonItem)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to set lastExitReason");
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, "lastExitDetailInfo",
        CreateEtsLastExitDetailInfo(env, launchParam.lastExitDetailInfo))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to set lastExitDetailInfo");
        return false;
    }
    return true;
}
} // namespace

bool WrapLaunchParam(ani_env *env, const AAFwk::LaunchParam &launchParam, ani_object &object)
{
    ani_method method = nullptr;
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null env");
        return false;
    }
    if ((status = env->FindClass(CLASSNAME_LAUNCHPARAM, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to find lanchParam Class, status: %{public}d", status);
        return false;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null cls");
        return false;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to find method, status: %{public}d", status);
        return false;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null method");
        return false;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to create object, status: %{public}d", status);
        return false;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null object");
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Ref(
        object, "lastExitMessage", GetAniString(env, launchParam.lastExitMessage))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to set lastExitMessage");
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Ref(
        object, "launchReasonMessage", GetAniString(env, launchParam.launchReasonMessage))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Failed to set launchReasonMessage");
        return false;
    }
    return WrapLaunchParamInner(env, launchParam, object);
}
} // namespace AbilityRuntime
} // namespace OHOS
