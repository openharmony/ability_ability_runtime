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

#include "want_utils.h"

#include "hilog_tag_wrapper.h"
#include "want_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

AbilityRuntime_ErrorCode CheckWant(AbilityBase_Want *want)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CheckWant called");
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null want");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    AbilityBase_Element element = want->element;
    if (element.bundleName == nullptr || element.abilityName == nullptr || element.moduleName == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "bundleName or abilityName or moduleName null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

#ifdef __cplusplus
}
#endif