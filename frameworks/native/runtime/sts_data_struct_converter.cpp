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

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

ani_object CreateStsLaunchParam(ani_env* env, const AAFwk::LaunchParam& launchParam)
{
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_string string = nullptr;
    ani_status status = ANI_ERROR;
    ani_object object = nullptr;
    ani_class cls = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/AbilityConstant/AbilityConstant/LaunchParam;", &cls)) != ANI_OK) {
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
    // TODO
    env->Class_FindField(cls, "lastExitMessage", &field);
    env->String_NewUTF8(launchParam.lastExitMessage.c_str(), launchParam.lastExitMessage.size(), &string);
    env->Object_SetField_Ref(object, field, string);
    return object;
}
} // namespace AbilityRuntime
} // namespace OHOS
