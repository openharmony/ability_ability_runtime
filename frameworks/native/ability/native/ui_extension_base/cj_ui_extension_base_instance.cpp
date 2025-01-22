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

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
#ifndef CJ_EXPORT
#ifndef __WINDOWS__
#define CJ_EXPORT __attribute__((visibility("default")))
#else
#define CJ_EXPORT __declspec(dllexport)
#endif
#endif
} // namespace

extern "C" {
CJ_EXPORT int32_t FFICJExtSessionLoadContent()
{
    return 0;
}

CJ_EXPORT int32_t FFICJExtSessionTerminateSelf()
{
    return 0;
}

CJ_EXPORT int32_t FFICJExtSessionTerminateSelfWithResult()
{
    return 0;
}

CJ_EXPORT int32_t FFICJExtSessionSetWindowPrivacyMode()
{
    return 0;
}

CJ_EXPORT int32_t FFICJExtSessionStartAbilityByType()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtAbilityGetContext()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxStartAbility()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxStartAbilityWithOpt()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxStartAbilityForRes()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxStartAbilityForResWithOpt()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxConnectServiceExtensionAbility()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxDisconnectServiceExtensionAbility()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxTerminateSelf()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxTerminateSelfWithResult()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxReportDrawnCompleted()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxOpenAtomicService()
{
    return 0;
}

CJ_EXPORT int32_t FFICJUIExtCtxOpenLink()
{
    return 0;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
