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

#ifndef OHOS_ABILITY_RUNTIME_UI_EXTENSION_CONTENT_SESSION_MODULE_H
#define OHOS_ABILITY_RUNTIME_UI_EXTENSION_CONTENT_SESSION_MODULE_H

#include <memory>

#include "ability_context.h"
#include "ani.h"
#include "ets_ui_extension_content_session.h"
#include "js_ui_extension_content_session.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsUiExtensionContentSessionModule {
public:
    EtsUiExtensionContentSessionModule() = default;
    ~EtsUiExtensionContentSessionModule() = default;

    EtsUiExtensionContentSessionModule(const EtsUiExtensionContentSessionModule &) = delete;
    EtsUiExtensionContentSessionModule(EtsUiExtensionContentSessionModule &&) = delete;
    EtsUiExtensionContentSessionModule &operator=(const EtsUiExtensionContentSessionModule &) = delete;
    EtsUiExtensionContentSessionModule &operator=(EtsUiExtensionContentSessionModule &&) = delete;

    static ani_object NativeTransferStatic(ani_env *aniEnv, ani_object aniObj, ani_object input);
    static ani_object NativeTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input);

private:
    static bool IsInstanceOf(ani_env *aniEnv, ani_object aniObj);
    static ani_object CreateDynamicObject(
        ani_env *aniEnv, ani_class aniCls, EtsUIExtensionContentSession *etsContentSession);
};

void EtsUiExtensionContentSessionModuleInit(ani_env *aniEnv);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_UI_EXTENSION_CONTENT_SESSION_MODULE_H
