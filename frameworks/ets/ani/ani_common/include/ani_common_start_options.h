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

#ifndef OHOS_ABILITY_RUNTIME_ANI_COMMON_START_OPTIONS_H
#define OHOS_ABILITY_RUNTIME_ANI_COMMON_START_OPTIONS_H

#include "ani_common_util.h"
#include "start_options.h"
#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
#include "pixel_map_ani.h"
#include "image_ani_utils.h"
#endif

namespace OHOS {
namespace AppExecFwk {

bool UnwrapStartOptionsWithProcessOption(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions);
bool UnwrapStartOptions(ani_env *env, ani_object param, AAFwk::StartOptions &startOptions);
bool UnwrapProcessOptions(ani_env *env, ani_object param, std::shared_ptr<AAFwk::ProcessOptions> &processOptions);

#ifdef START_WINDOW_OPTIONS_WITH_PIXELMAP
bool UnwrapPixelMapByPropertyName(
    ani_env *env, ani_object EnvObject, const char *propertyName, std::shared_ptr<Media::PixelMap> &value);
bool UnwrapPixelMapFromAni(ani_env *env, ani_object param, std::shared_ptr<Media::PixelMap> &value);
#endif

bool UnwrapStartWindowOption(ani_env *env, ani_object param,
    std::shared_ptr<AAFwk::StartWindowOption> &startWindowOption);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_NAPI_COMMON_START_OPTIONS_H