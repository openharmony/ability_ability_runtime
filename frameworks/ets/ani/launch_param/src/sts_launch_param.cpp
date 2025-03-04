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
#include "sts_launch_param.h"
#include "hilog_tag_wrapper.h"
namespace OHOS {
namespace AbilityConstantSts {

using namespace OHOS::AbilityRuntime;

ani_object WrapLaunchParam(ani_env *env, const OHOS::AAFwk::LaunchReason launchReason,
    const OHOS::AAFwk::LastExitReason lastExitReason,
    const std::string &lastExitMessage)
{
    TAG_LOGI(AAFwkTag::APPKIT, "WrapLaunchParam called");

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LEntryAbility/LaunchParamInner;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find LaunchParam failed status : %{public}d", status);
        return {};
    }
    ani_method method = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod ctor failed status : %{public}d", status);
        return {};
    }
    ani_object object = nullptr;
    if (env->Object_New(cls, method, &object) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New failed status : %{public}d", status);
        return {};
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Object_New success");

    //LaunchReason
    ani_method setReasonMethod;
    status = env->Class_FindMethod(cls, "<set>launchReason", nullptr, &setReasonMethod);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Class_FindMethod configObj failed");
    }

    status = env->Object_CallMethod_Void(object, setReasonMethod, (int)launchReason);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Object_CallMethod_Void failed");
    }
    //LastExitReason
    ani_method setExitReasonMethod;
    status = env->Class_FindMethod(cls, "<set>lastExitReason", nullptr, &setExitReasonMethod);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Class_FindMethod configObj failed");
    }

    status = env->Object_CallMethod_Void(object, setExitReasonMethod, (int)lastExitReason);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Object_CallMethod_Void failed");
    }

    //lastExitMessage
    ani_method setlastExitMessage;
    status = env->Class_FindMethod(cls, "<set>lastExitMessage", nullptr, &setlastExitMessage);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Class_FindMethod configObj failed");
    }
    ani_string aniStr;
    env->String_NewUTF8(lastExitMessage.c_str(), lastExitMessage.length(), &aniStr);
    status = env->Object_CallMethod_Void(object, setlastExitMessage, aniStr);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Object_CallMethod_Void failed");
    }

    return object;
}
} // namespace AbilityConstantSts
} // namespace OHOS
