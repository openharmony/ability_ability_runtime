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

#ifndef ABILITY_RUNTIME_ABILITY_BUSINESS_ERROR_UTILS_H
#define ABILITY_RUNTIME_ABILITY_BUSINESS_ERROR_UTILS_H

#include <stdint.h>

#include "ability_runtime_common.h"

AbilityRuntime_ErrorCode ConvertToCommonBusinessErrorCode(int32_t abilityManagerErrorCode);

AbilityRuntime_ErrorCode ConvertToAPI18BusinessErrorCode(int32_t abilityManagerErrorCode);

#endif // ABILITY_RUNTIME_ABILITY_BUSINESS_ERROR_UTILS_H
