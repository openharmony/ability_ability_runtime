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

#include "ui_ability_lifecycle_manager.h"

#include "ability_record.h"
#include "element_name.h"
#include "mock_my_flag.h"

namespace OHOS {
namespace AAFwk {
bool UIAbilityLifecycleManager::IsCallerInStatusBar(const std::string &instanceKey)
{
    return MyFlag::GetInstance().isCallerInStatusBar_;
}

std::vector<std::shared_ptr<AbilityRecord>> UIAbilityLifecycleManager::GetAbilityRecordsByName(
    const AppExecFwk::ElementName &element)
{
    return MyFlag::GetInstance().abilityRecords_;
}
}  // namespace AAFwk
}  // namespace OHOS