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

#ifndef OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_EXTENSION_CONTEXT_H

#include "auto_fill_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsAutoFillExtensionContext final {
public:
    explicit EtsAutoFillExtensionContext(std::shared_ptr<AutoFillExtensionContext> context)
        : context_(context) {}
    virtual ~EtsAutoFillExtensionContext() = default;

    static ani_object SetEtsAutoFillExtensionContext(ani_env *env, std::shared_ptr<AutoFillExtensionContext> context);
    static EtsAutoFillExtensionContext *GetEtsAutoFillExtensionContext(ani_env *env, ani_object object);
    static void Clean(ani_env *env, ani_object object);
    static void ReloadInModal(ani_env *env, ani_object object, ani_object customDataObj, ani_object callback);
    static ani_object CreateEtsAutoFillExtensionContext(ani_env *env,
        std::shared_ptr<AutoFillExtensionContext> context);

private:
    void OnReloadInModal(ani_env *env, ani_object object, ani_object customDataObj, ani_object callback);
    std::weak_ptr<AutoFillExtensionContext> context_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_EXTENSION_CONTEXT_H