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

#ifndef MOCK_SYSTEM_ABILITY_H
#define MOCK_SYSTEM_ABILITY_H

#include <string>

#include "iremote_object.h"
#include "refbase.h"

namespace OHOS {
enum {
    ABILITY_MGR_SERVICE_ID = 180,
    BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401,
    DISTRIBUTED_SCHED_SA_ID = 1401,
    BACKGROUND_TASK_MANAGER_SERVICE_ID = 1903,
    MULTIMODAL_INPUT_SERVICE_ID = 3101,
    WINDOW_MANAGER_SERVICE_ID = 4606,
};

#define DECLEAR_SYSTEM_ABILITY(className) \
public: \
std::string GetClassName() { \
return #className; \
}

class SystemAbility {
public:
    SystemAbility() {}
    SystemAbility(int32_t systemAbilityId, bool runOnCreate = false) {}
    static bool MakeAndRegisterAbility(SystemAbility* systemAbility)
    {
        return false;
    }

    bool AddSystemAbilityListener(int32_t systemAbilityId)
    {
        return false;
    }

protected:
    virtual void OnStart() {}

    virtual void OnStop() {}

    virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) {}

    virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) {}

    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId)
    {
        return nullptr;
    }

    bool Publish(sptr<IRemoteObject> systemAbility)
    {
        return false;
    }
};
}
#endif