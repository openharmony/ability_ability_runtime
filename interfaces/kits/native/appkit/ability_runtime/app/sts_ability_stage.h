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

#ifndef OHOS_ABILITY_RUNTIME_STS_ABILITY_STAGE_H
#define OHOS_ABILITY_RUNTIME_STS_ABILITY_STAGE_H

#include "ability_delegator_infos.h"

#include <memory>
#include <vector>

#include "ability_stage.h"
#include "configuration.h"
#include "js_startup_task.h"
#include "resource_manager.h"
#include "nlohmann/json.hpp"
#include "native_engine/native_value.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
class STSAbilityStage : public AbilityStage {
public:
    static std::shared_ptr<AbilityStage> Create(
        const std::unique_ptr<Runtime>& runtime, const AppExecFwk::HapModuleInfo& hapModuleInfo);

    STSAbilityStage(STSRuntime& stsRuntime, std::unique_ptr<STSNativeReference>&& stsAbilityStageObj);
    ~STSAbilityStage() override;

    void Init(const std::shared_ptr<Context> &context,
        const std::weak_ptr<AppExecFwk::OHOSApplication> application) override;

    void OnCreate(const AAFwk::Want &want) const override;

    void OnDestroy() const override;

    std::string OnAcceptWant(const AAFwk::Want &want) override;

    std::string OnNewProcessRequest(const AAFwk::Want &want) override;

    void OnConfigurationUpdated(const AppExecFwk::Configuration& configuration) override;

    void OnMemoryLevel(int32_t level) override;

    int32_t RunAutoStartupTask(const std::function<void()> &callback, bool &isAsyncCallback,
        const std::shared_ptr<Context> &stageContext) override;

private:

    bool CallObjectMethod(bool withResult, const char* name, const char* signature, ...) const;

    std::shared_ptr<AppExecFwk::ETSDelegatorAbilityStageProperty> CreateStageProperty() const;

    std::string GetHapModuleProp(const std::string &propName) const;

    static bool UseCommonChunk(const AppExecFwk::HapModuleInfo& hapModuleInfo);

    std::unique_ptr<STSNativeReference> LoadJsOhmUrl(const std::string &srcEntry, const std::string &ohmUrl,
        const std::string &moduleName, const std::string &hapPath, bool esmodule);

    std::unique_ptr<STSNativeReference> LoadJsSrcEntry(const std::string &srcEntry);

    bool LoadJsStartupConfig(const std::string &srcEntry);

    int32_t RegisterAppStartupTask(const std::shared_ptr<AppExecFwk::HapModuleInfo>& hapModuleInfo);

    static int32_t RunAutoStartupTaskInner(const std::function<void()> &callback, bool &isAsyncCallback);

    STSRuntime& stsRuntime_;

    void SetJsAbilityStage(const std::shared_ptr<Context> &context,
        const std::weak_ptr<AppExecFwk::OHOSApplication> application);
    std::unique_ptr<STSNativeReference> stsAbilityStageObj_;
    ani_object stageObj_ = nullptr;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_STS_ABILITY_STAGE_H
