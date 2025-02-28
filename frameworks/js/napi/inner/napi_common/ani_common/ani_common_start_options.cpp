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

#include "ani_common_start_options.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
int32_t GetIntOrUndefined(ani_env *env, ani_object param, const char *name)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_int res = 0;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return 0;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return 0;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::JSNAPI, "%{public}s : undefined", name);
        return 0;
    } 
    if ((status = env->Object_CallMethodByName_Int(
        reinterpret_cast<ani_object>(obj), "intValue", nullptr, &res)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return 0;
    }
    return res;
}

bool AniUnwrapStartOptionsWithProcessOption(ani_env* env, ani_object param, AAFwk::StartOptions &startOptions)
{
    AniUnwrapStartOptions(env, param, startOptions);
    return true;
}

bool AniUnwrapStartOptions(ani_env* env, ani_object param, AAFwk::StartOptions &startOptions)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null env");
        return false;
    }

    int32_t displayId = GetIntOrUndefined(env, param, "displayId");
    startOptions.SetDisplayID(displayId);
    TAG_LOGI(AAFwkTag::JSNAPI, "displayId %{public}d", displayId);

    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS