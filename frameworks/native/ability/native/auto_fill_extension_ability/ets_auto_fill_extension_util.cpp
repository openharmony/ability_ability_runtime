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

#include "ets_auto_fill_extension_util.h"

#include "ani_common_execute_result.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "hilog_tag_wrapper.h"
#include "want_params.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
constexpr const char* CUSTOM_DATA_INNER_CLASS_NAME = "application.CustomData.CustomDataInner";

ani_object EtsAutoFillExtensionUtil::WrapCustomData(ani_env *env, const CustomData &customdata)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return nullptr;
    }

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method ctor = nullptr;
    ani_object objValue = {};

    if ((status = env->FindClass(CUSTOM_DATA_INNER_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null cls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) != ANI_OK || ctor == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Class_FindMethod status: %{public}d or null ctor", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, ctor, &objValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return nullptr;
    }
    if (objValue == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null objValue");
        return nullptr;
    }
    if (!SetRefProperty(env, objValue, "data", WrapWantParams(env, customdata.data))) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "SetRefProperty failed");
        return nullptr;
    }
    return objValue;
}
} // namespace AbilityRuntime
} // namespace OHOS