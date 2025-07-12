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
namespace AppExecFwk {
struct ETSNativeReference;
}
namespace AbilityRuntime {
class ServiceExtension;
class ETSRuntime;
/**
 * @brief Basic ets extension common components.
 */
class EtsExtensionCommon : public ExtensionCommon,
                            public std::enable_shared_from_this<EtsExtensionCommon> {
public:
    EtsExtensionCommon(ETSRuntime &etsRuntime, AppExecFwk::ETSNativeReference &etsObj,
        const std::shared_ptr<AppExecFwk::ETSNativeReference> &shellContextRef);

    virtual ~EtsExtensionCommon() override;

    /**
     * @brief Create JsServiceExtension.
     *
     * @param etsRuntime The runtime.
     * @param etsObj The ets object instance.
     * @return The JsServiceExtension instance.
     */
    static std::shared_ptr<EtsExtensionCommon> Create(ETSRuntime &etsRuntime, AppExecFwk::ETSNativeReference &etsObj,
        const std::shared_ptr<AppExecFwk::ETSNativeReference> &shellContextRef);

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
    ETSRuntime& etsRuntime_;
    AppExecFwk::ETSNativeReference& etsObj_;
    std::shared_ptr<AppExecFwk::ETSNativeReference> shellContextRef_ = nullptr;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ETS_EXTENSION_COMMON_H
