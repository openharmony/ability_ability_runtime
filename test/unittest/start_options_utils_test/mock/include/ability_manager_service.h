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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_SERVICE_H
#define OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_SERVICE_H

#include <memory>
#include <singleton.h>

#include "ui_ability_lifecycle_manager.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class AbilityManagerService
 * AbilityManagerService provides a facility for managing ability life cycle.
 */
class AbilityManagerService : public std::enable_shared_from_this<AbilityManagerService> {
    DECLARE_DELAYED_SINGLETON(AbilityManagerService)
public:
    bool CheckCallingTokenId(const std::string &bundleName, int32_t userId, int32_t appIndex);
    std::shared_ptr<UIAbilityLifecycleManager> GetUIAbilityManagerByUid(int32_t uid);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_SERVICE_H
