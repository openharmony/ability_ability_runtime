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

#include "mock_ability_manager_client.h"

namespace OHOS {
namespace AAFwk {

std::shared_ptr<AbilityManagerClient> AbilityManagerClient::GetInstance()
{
    if (isNullInstance) {
        return nullptr;
    }
    if (instance_) {
        return instance_;
    }
    instance_ = std::shared_ptr<AbilityManagerClient>(new AbilityManagerClient());
    return instance_;
}

std::shared_ptr<IAbilityManagerCollaborator> AbilityManagerClient::GetAbilityManagerCollaborator()
{
    return collaborator_;
}

bool AbilityManagerClient::isNullInstance = false;
std::shared_ptr<AbilityManagerClient> AbilityManagerClient::instance_ = nullptr;
std::shared_ptr<IAbilityManagerCollaborator> AbilityManagerClient::collaborator_ = nullptr;
}  // namespace AAFwk
}  // namespace OHOS