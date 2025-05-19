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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_RESOURCE_MANAGER_HELPER_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_RESOURCE_MANAGER_HELPER_H

#include "options.h"
#include "res_config.h"
#include "resource_manager.h"

namespace OHOS {
namespace AbilityRuntime {
class ResourceManagerHelper {
public:
    ResourceManagerHelper() = default;
    ~ResourceManagerHelper() = default;

    static ResourceManagerHelper &GetInstance();
    void Init(const Options &options);
    void GetResConfig(Global::Resource::ResConfig &resConfig, bool isCreateModuleContext = false);
    void AddSystemResource(std::shared_ptr<Global::Resource::ResourceManager> &resMgr);

private:
    Options options_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_RESOURCE_MANAGER_HELPER_H
