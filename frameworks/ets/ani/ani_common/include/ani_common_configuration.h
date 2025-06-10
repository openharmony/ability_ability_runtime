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

#ifndef OHOS_ABILITY_RUNTIME_NAPI_COMMON_CONFIGURATION_H
#define OHOS_ABILITY_RUNTIME_NAPI_COMMON_CONFIGURATION_H

#include "configuration.h"
#include "ani_common_util.h"

namespace OHOS {
namespace AppExecFwk {

void SetBasicConfiguration(
    ani_env *env, ani_class cls, ani_object object, const AppExecFwk::Configuration &configuration);
void SetAdditionalConfiguration(
    ani_env *env, ani_class cls, ani_object object, const AppExecFwk::Configuration &configuration);
ani_object WrapConfiguration(ani_env *env, const AppExecFwk::Configuration &configuration);
bool UnwrapConfiguration(ani_env *env, ani_object param, Configuration &config);

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_NAPI_COMMON_CONFIGURATION_H
