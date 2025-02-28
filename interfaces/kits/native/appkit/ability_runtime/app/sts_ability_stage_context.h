/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_STS_ABILITY_STAGE_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_STS_ABILITY_STAGE_CONTEXT_H

#include "configuration.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AppExecFwk {
class OHOSApplication;
}
namespace AbilityRuntime {

constexpr const char* STS_ABILITY_STAGE_CONTEXT_CLASS_NAME = "LAbilityStageHand/AbilityStageContext;";
constexpr const char* STS_CONFIGURATION_CLASS_NAME = "LAbilityStageHand/ConfigurationInner;";
constexpr const char* STS_HAPMODULEINFO_CLASS_NAME = "LAbilityStageHand/HapModuleInfo;";
constexpr const char* STS_ABILITY_STAGE_CLASS_NAME = "LAbilityStageHand/AbilityStage;";

class Context;
class STSAbilityStageContext final {
public:
    explicit STSAbilityStageContext(const std::shared_ptr<Context>& context) : context_(context) {}
    ~STSAbilityStageContext() = default;

    static void ConfigurationUpdated(ani_env* env, const std::shared_ptr<AppExecFwk::Configuration> &config);

    std::shared_ptr<Context> GetContext()
    {
        return context_.lock();
    }
    static ani_object CreateStsAbilityStageContext(ani_env* env, std::shared_ptr<Context> context,
        std::weak_ptr<AppExecFwk::OHOSApplication> application);
    static ani_object Createfiguration(ani_env* env, const std::shared_ptr<AppExecFwk::Configuration> &configuration);
    static void ResetEnv(ani_env* env);

private:
    static ani_object Createfiguration(ani_env* env, const std::shared_ptr<Context> &context);
    static ani_object CreateHapModuleInfo(ani_env* env, const std::shared_ptr<Context> &context);
    static void BindApplicationCtx(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
        std::weak_ptr<AppExecFwk::OHOSApplication> application);

    static void BindParentProperty(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
        std::shared_ptr<Context> context);

private:
    std::weak_ptr<Context> context_;
    static ani_ref stsAbilityStageContextObj_;
};

}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_STS_ABILITY_STAGE_CONTEXT_H
