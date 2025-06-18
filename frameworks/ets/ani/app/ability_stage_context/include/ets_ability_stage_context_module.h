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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_STAGE_CONTEXT_MODULE_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_STAGE_CONTEXT_MODULE_H

#include <memory>
#include "ani.h"
#include "ability_stage_context.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsAbilityStageContextModule {
public:
    EtsAbilityStageContextModule() = default;
    ~EtsAbilityStageContextModule() = default;

    EtsAbilityStageContextModule(const EtsAbilityStageContextModule&) = delete;
    EtsAbilityStageContextModule(EtsAbilityStageContextModule&&) = delete;
    EtsAbilityStageContextModule& operator=(const EtsAbilityStageContextModule&) = delete;
    EtsAbilityStageContextModule& operator=(EtsAbilityStageContextModule&&) = delete;

    static ani_object NativeTransferStatic(ani_env *aniEnv, ani_object aniObj, ani_object input);
    static ani_object NativeTransferDynamic(ani_env *aniEnv, ani_object aniObj, ani_object input);

private:
    static bool IsInstanceOf(ani_env *aniEnv, ani_object aniObj);
    static std::unique_ptr<NativeReference> GetOrCreateNativeReference(napi_env napiEnv,
        std::shared_ptr<AbilityStageContext> abilityStageContext);
    static std::unique_ptr<NativeReference> CreateNativeReference(napi_env napiEnv,
        std::shared_ptr<AbilityStageContext> abilityStageContext);
};

void EtsAbilityStageContextModuleInit(ani_env *aniEnv);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_ABILITY_STAGE_CONTEXT_MODULE_H
