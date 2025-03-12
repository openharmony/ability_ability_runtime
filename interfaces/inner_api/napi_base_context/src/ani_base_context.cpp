/*
* Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ani_base_context.h"

namespace OHOS {
namespace AbilityRuntime {
ani_status IsStageContext(ani_env* env, ani_object object, ani_boolean& stageMode)
{
    if (env == nullptr) {
        std::cerr << "env is nullptr" << std::endl;
        return ANI_ERROR;
    }

    if (env->Object_GetFieldByName_Boolean(object, "stageMode", &stageMode) != ANI_OK) {
        std::cerr << "GetField failed" << std::endl;
        return ANI_ERROR;
    }

    std::cerr << "GetField, stageMode : " << std::to_string(stageMode) << std::endl;
    return ANI_OK;
}

std::shared_ptr<Context> GetStageModeContext(ani_env* env, ani_object object)
{
    if (env == nullptr) {
        std::cerr << "env is nullptr" << std::endl;
        return nullptr;
    }

    ani_long nativeContextLong;
    if ((env->Object_GetFieldByName_Long(object, "nativeContext", &nativeContextLong)) != ANI_OK) {
        std::cerr << "Object_GetField_Long failed" << std::endl;
        return nullptr;
    }

    std::shared_ptr<Context> ptr((Context*)nativeContextLong);

    return ptr;
}

AppExecFwk::Ability* GetCurrentAbility(ani_env* env)
{
    return nullptr;
}
} // namespace AbilityRuntime
} // namespace OHOS