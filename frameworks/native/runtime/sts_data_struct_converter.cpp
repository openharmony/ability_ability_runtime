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

#include "sts_data_struct_converter.h"

#include "common_func.h"
#include "configuration_convertor.h"
#include "hilog_tag_wrapper.h"
#include "ani_enum_convert.h"
namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

namespace {
constexpr const char* LAUNCH_PARAM_IMPL_CLASS_NAME = "L@ohos/app/ability/AbilityConstant/LaunchParamImpl;";
constexpr const char* LAUNCH_REASON_ENUM_NAME = "L@ohos/app/ability/AbilityConstant/AbilityConstant/LaunchReason;";
constexpr const char* LAST_EXIT_REASON_ENUM_NAME =
    "L@ohos/app/ability/AbilityConstant/AbilityConstant/LastExitReason;";
constexpr const char* LAST_EXIT_DETAIL_INFO_IMPL_CLASS_NAME =
    "L@ohos/app/ability/AbilityConstant/LastExitDetailInfoImpl;";
}

ani_string GetAniString(ani_env *env, const std::string &str)
{
    ani_string aniStr = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status: %{public}d", status);
        return nullptr;
    }
    return aniStr;
}

ani_object CreateStsLastExitDetailInfo(ani_env* env, const AAFwk::LastExitDetailInfo& lastExitDetailInfo)
{
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_string string = nullptr;
    ani_status status = ANI_ERROR;
    ani_object object = nullptr;
    ani_class cls = nullptr;
    if ((status = env->FindClass(LAST_EXIT_DETAIL_INFO_IMPL_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null cls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
        return nullptr;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null method");
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null object");
        return nullptr;
    }
    env->Object_SetPropertyByName_Ref(object, "pid", GetAniString(env, std::to_string(lastExitDetailInfo.pid)));
    env->Object_SetPropertyByName_Ref(object, "processName", GetAniString(env, lastExitDetailInfo.processName));
    env->Object_SetPropertyByName_Ref(object, "uid", GetAniString(env, std::to_string(lastExitDetailInfo.uid)));
    env->Object_SetPropertyByName_Ref(object, "exitSubReason",
        GetAniString(env, std::to_string(lastExitDetailInfo.exitSubReason)));
    env->Object_SetPropertyByName_Ref(object, "exitMsg", GetAniString(env, lastExitDetailInfo.exitMsg));
    env->Object_SetPropertyByName_Ref(object, "rss", GetAniString(env, std::to_string(lastExitDetailInfo.rss)));
    env->Object_SetPropertyByName_Ref(object, "pss", GetAniString(env, std::to_string(lastExitDetailInfo.pss)));
    env->Object_SetPropertyByName_Ref(object, "timestamp",
        GetAniString(env, std::to_string(lastExitDetailInfo.timestamp)));

    return object;
}

ani_object CreateStsLaunchParam(ani_env* env, const AAFwk::LaunchParam& launchParam)
{
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_string string = nullptr;
    ani_status status = ANI_ERROR;
    ani_object object = nullptr;
    ani_class cls = nullptr;
    if ((status = env->FindClass(LAUNCH_PARAM_IMPL_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cls");
        return nullptr;
    }

    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null method");
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null object");
        return nullptr;
    }
    env->Object_SetPropertyByName_Ref(object, "lastExitMessage", GetAniString(env, launchParam.lastExitMessage));

    ani_enum_item launchReasonItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvertNativeToSts(env,
        LAUNCH_REASON_ENUM_NAME, launchParam.launchReason, launchReasonItem);
    env->Object_SetPropertyByName_Ref(object, "launchReason", launchReasonItem);

    ani_enum_item lastExitReasonItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvertNativeToSts(env,
        LAST_EXIT_REASON_ENUM_NAME, launchParam.lastExitReason, lastExitReasonItem);
    env->Object_SetPropertyByName_Ref(object, "lastExitReason", lastExitReasonItem);
    env->Object_SetPropertyByName_Ref(object, "lastExitDetailInfo",
        CreateStsLastExitDetailInfo(env, launchParam.lastExitDetailInfo));

    return object;
}
} // namespace AbilityRuntime
} // namespace OHOS
