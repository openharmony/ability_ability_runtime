/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CJ_WANT_AGENT_UTILS_FFI_H
#define CJ_WANT_AGENT_UTILS_FFI_H

#include <string>

#include "want_agent_constant.h"
#include "want_agent_helper.h"
#include "cj_want_ffi.h"
#include "cj_common_ffi.h"

namespace OHOS {
namespace FfiWantAgent {

struct CJWantArr {
    WantHandle* head;
    int64_t size;
};

struct CJWantAgentInfo {
    CJWantArr wants;
    int32_t actionType;
    int32_t requestCode;
    CArrI32 actionFlags;
    // Record<string, Object>
    char* extraInfos;
};

struct CJTriggerInfo {
    int32_t code;
    WantHandle want;
    bool hasWant;
    char* permission;
    // Record<string, Object>
    char* extraInfos;
};

struct CJCompleteData {
    int64_t info;
    WantHandle want;
    int32_t finalCode;
    char* finalData;
    // Record<string, Object>
    char* extraInfo;
};

}
}
#endif // CJ_WANT_AGENT_UTILS_FFI_H