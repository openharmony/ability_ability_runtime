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

bool UnwrapStartOptionsWithProcessOption(ani_env* env, ani_object param, AAFwk::StartOptions &startOptions)
{
    UnwrapStartOptions(env, param, startOptions);
    return true;
}

bool UnwrapStartOptions(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null env");
        return false;
    }
    ani_double displayId = 0.0;
    if (GetDoubleOrUndefined(env, param, "displayId", displayId)) {
        startOptions.SetDisplayID(static_cast<int>(displayId));
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS