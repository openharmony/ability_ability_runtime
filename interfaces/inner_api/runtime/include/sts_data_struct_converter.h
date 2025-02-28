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

#ifndef OHOS_ABILITY_RUNTIME_STS_DATA_STRUCT_CONVERTER_H
#define OHOS_ABILITY_RUNTIME_STS_DATA_STRUCT_CONVERTER_H

#include "ability_info.h"
#include "application_info.h"
#include "launch_param.h"
#include "hap_module_info.h"
#include "want.h"
#include "configuration.h"

#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
ani_object CreateStsLaunchParam(ani_env* env, const AAFwk::LaunchParam& launchParam);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STS_DATA_STRUCT_CONVERTER_H
