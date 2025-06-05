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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_INTERFACE_H
#define MOCK_OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_INTERFACE_H

#include <vector>

#include "auto_startup_info.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AAFwk {
class IAbilityManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.AbilityManager")

    OH_MOCK_VIRTUAL_METHOD(int32_t, IAbilityManager, SetApplicationAutoStartupByEDM, const AbilityRuntime::AutoStartupInfo &, bool);
    OH_MOCK_VIRTUAL_METHOD(int32_t, IAbilityManager, CancelApplicationAutoStartupByEDM, const AbilityRuntime::AutoStartupInfo &, bool);

    virtual int32_t QueryAllAutoStartupApplications(std::vector<AbilityRuntime::AutoStartupInfo> &infoList)
    {
        return 0;
    }
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_INTERFACE_H
 