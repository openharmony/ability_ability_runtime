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

#ifndef OHOS_ABILITY_RUNTIME_ETS_EXTENSION_COMMON_H
#define OHOS_ABILITY_RUNTIME_ETS_EXTENSION_COMMON_H

#include "configuration.h"
#include "service_extension.h"

namespace OHOS {
namespace AbilityRuntime {
struct STSNativeReference;
class ServiceExtension;
class STSRuntime;
/**
 * @brief Basic ets extension common components.
 */
class EtsExtensionCommon : public ExtensionCommon,
                            public std::enable_shared_from_this<EtsExtensionCommon> {
public:
    EtsExtensionCommon(STSRuntime &stsRuntime, STSNativeReference &stsObj,
        const std::shared_ptr<STSNativeReference> &shellContextRef);

    virtual ~EtsExtensionCommon() override;

    /**
     * @brief Create JsServiceExtension.
     *
     * @param stsRuntime The runtime.
     * @param etsObj The ets object instance.
     * @return The JsServiceExtension instance.
     */
    static std::shared_ptr<EtsExtensionCommon> Create(STSRuntime &stsRuntime, STSNativeReference &stsObj,
        const std::shared_ptr<STSNativeReference> &shellContextRef);

    /**
     * @brief Called when the system configuration is updated.
     *
     * @param configuration Indicates the updated configuration information.
     */
    void OnConfigurationUpdated(const std::shared_ptr<AppExecFwk::Configuration> &fullConfig) override;

    /**
     * @brief Notify current memory level.
     *
     * @param level Current memory level.
     */
    void OnMemoryLevel(int level) override;

private:
    void CallObjectMethod(const char *name, const char *signature, ...);

private:
    STSRuntime& stsRuntime_;
    STSNativeReference& stsObj_;
    std::shared_ptr<STSNativeReference> shellContextRef_ = nullptr;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ETS_EXTENSION_COMMON_H
