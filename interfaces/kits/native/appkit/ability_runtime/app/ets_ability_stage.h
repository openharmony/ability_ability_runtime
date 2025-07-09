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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_STAGE_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_STAGE_H

#include <memory>
#include <vector>

#include "ability_delegator_infos.h"
#include "ability_stage.h"
#include "configuration.h"
#include "ets_native_reference.h"
#include "ets_runtime.h"
#include "native_engine/native_value.h"
#include "resource_manager.h"

namespace OHOS {
namespace AbilityRuntime {
class ETSAbilityStage : public AbilityStage {
public:
    static AbilityStage *Create(
        const std::unique_ptr<Runtime>& runtime, const AppExecFwk::HapModuleInfo& hapModuleInfo);

    ETSAbilityStage(ETSRuntime &etsRuntime, std::unique_ptr<AppExecFwk::ETSNativeReference> &&ETSAbilityStageObj);
    ~ETSAbilityStage() override {}

    void Init(const std::shared_ptr<Context> &context,
        const std::weak_ptr<AppExecFwk::OHOSApplication> application) override;

    void OnCreate(const AAFwk::Want &want) const override;

    void OnDestroy() const override;

    void OnConfigurationUpdated(const AppExecFwk::Configuration &configuration) override;

private:
    bool CallObjectMethod(bool withResult, const char *name, const char *signature, ...) const;

    std::shared_ptr<AppExecFwk::EtsDelegatorAbilityStageProperty> CreateStageProperty() const;

    std::string GetHapModuleProp(const std::string &propName) const;

    void SetEtsAbilityStage(const std::shared_ptr<Context> &context);

    ETSRuntime& etsRuntime_;
    std::unique_ptr<AppExecFwk::ETSNativeReference> etsAbilityStageObj_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ETS_ABILITY_STAGE_H
