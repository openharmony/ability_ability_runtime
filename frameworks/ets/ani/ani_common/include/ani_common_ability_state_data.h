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

#ifndef OHOS_ABILITY_RUNNTIME_ANICOMMON_ABILITY_STATE_DATA_H
#define OHOS_ABILITY_RUNNTIME_ANICOMMON_ABILITY_STATE_DATA_H

#include "sts_runtime.h"
#include "ability_state_data.h"

namespace OHOS {
namespace AppExecFwk {
    ani_object WrapAbilityStateData(ani_env *env, const AbilityStateData &data);
    ani_object WrapAbilityStateDataInner(ani_env *env, ani_class cls, ani_object object,
        const AbilityStateData &data);
    ani_object CreateAniAbilityStateDataArray(ani_env *env, const std::vector<AbilityStateData> &list);
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_ABILITY_RUNNTIME_ANICOMMON_ABILITY_STATE_DATA_H