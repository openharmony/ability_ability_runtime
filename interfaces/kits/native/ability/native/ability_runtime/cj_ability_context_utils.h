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

#ifndef OHOS_ABILITY_RUNTIME_CJ_ABILITY_CONTEXT_UTILS_H
#define OHOS_ABILITY_RUNTIME_CJ_ABILITY_CONTEXT_UTILS_H

#include <cstdint>

extern "C" {
using WantHandle = void*;

struct CJAbilityResult {
    int32_t resultCode;
    WantHandle wantHandle;
};

struct CJStartOptions {
    int32_t windowMode;
    int32_t displayId;
};

struct CJNewStartOptions {
    int32_t windowMode;
    int32_t displayId;
    bool withAnimation;
    int32_t windowLeft;
    int32_t windowTop;
    int32_t windowWidth;
    int32_t windowHeight;
};

struct CJAtomicServiceOptions {
    bool hasValue;
    int32_t flags;
    char* parameters;
    CJNewStartOptions startOptions;
};

struct CJOpenLinkOptions {
    bool hasValue;
    bool appLinkingOnly;
    char* parameters;
};
}
#endif // OHOS_ABILITY_RUNTIME_CJ_ABILITY_CONTEXT_UTILS_H