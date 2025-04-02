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
#define SETTER_METHOD_NAME(property) "<set>" #property

void ClassSetter(
    ani_env* env, ani_class cls, ani_object object, const char* setterName, ...)
{
    ani_status status = ANI_ERROR;
    ani_method setter;
    if ((status = env->Class_FindMethod(cls, setterName, nullptr, &setter)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    va_list args;
    va_start(args, setterName);
    if ((status = env->Object_CallMethod_Void_V(object, setter, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    va_end(args);
}

ani_string GetAniString(ani_env *env, const std::string &str)
{
    ani_string aniStr = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    return aniStr;
}

ani_object CreateStsLaunchParam(ani_env* env, const AAFwk::LaunchParam& launchParam)
{
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_string string = nullptr;
    ani_status status = ANI_ERROR;
    ani_object object = nullptr;
    ani_class cls = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/AbilityConstant/LaunchParamImpl;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cls");
    }

    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null method");
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null object");
        return nullptr;
    }
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(lastExitMessage), GetAniString(env, launchParam.lastExitMessage));
    ani_enum_item launchReasonItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToSts(env,
        "L@ohos/app/ability/AbilityConstant/AbilityConstant/LaunchReason;", launchParam.launchReason, launchReasonItem);
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(launchReason), launchReasonItem);
    ani_enum_item lastExitReasonItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToSts(env,
        "L@ohos/app/ability/AbilityConstant/AbilityConstant/LastExitReason;",
        launchParam.lastExitReason, lastExitReasonItem);
    ClassSetter(env, cls, object, SETTER_METHOD_NAME(lastExitReason), lastExitReasonItem);

    return object;
}
} // namespace AbilityRuntime
} // namespace OHOS
