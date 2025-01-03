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

#ifndef OHOS_ABILITY_RUNTIME_CJ_EXTENSION_COMMON_H
#define OHOS_ABILITY_RUNTIME_CJ_EXTENSION_COMMON_H

#include "configuration.h"
#include "service_extension.h"
#include "cj_ui_extension_object.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @brief Basic cj extension common components.
 */
class CJExtensionCommon : public ExtensionCommon,
                            public std::enable_shared_from_this<CJExtensionCommon> {
public:
    CJExtensionCommon(CJUIExtensionObject cjObj);

    virtual ~CJExtensionCommon() override = default;

    /**
     * @brief Create CJServiceExtension.
     *
     * @param cjObj The cangjie object.
     * @return The CJServiceExtension instance.
     */
    static std::shared_ptr<CJExtensionCommon> Create(CJUIExtensionObject cjObj);

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
    virtual void OnMemoryLevel(int level) override;
private:
    CJUIExtensionObject cjObj_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_CJ_EXTENSION_COMMON_H
