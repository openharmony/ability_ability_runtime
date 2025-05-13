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

#ifndef OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_CONTEXT_H

#include "form_extension_context.h"
#include "cj_extension_context.h"
#include "image_packer.h"
#include "cj_context.h"

namespace OHOS {
namespace AbilityRuntime {
class CJFormExtensionContext : public CJExtensionContext {
public:
    explicit CJFormExtensionContext(const std::shared_ptr<FormExtensionContext> &context)
        : CJExtensionContext(context, context->GetAbilityInfo()), context_(context)
    {}

    virtual ~CJFormExtensionContext() = default;

    std::shared_ptr<FormExtensionContext> GetContext()
    {
        return context_.lock();
    }
private:
    std::weak_ptr<FormExtensionContext> context_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_CONTEXT_H
