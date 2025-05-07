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

#ifndef OHOS_START_ABILITY_START_WITH_WAIT_OBSERVER_INTERFACE_H
#define OHOS_START_ABILITY_START_WITH_WAIT_OBSERVER_INTERFACE_H

#include "ability_start_with_wait_observer_data.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AAFwk {
class IAbilityStartWithWaitObserver : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.ability.IAbilityStartWithWaitObserver");

    virtual int32_t NotifyAATerminateWait(const AbilityStartWithWaitObserverData &abilityStartWithWaitData) = 0;
    enum class Message {
        NOTIFY_AA_TERMINATE_WAIT,
    };
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_START_ABILITY_START_WITH_WAIT_OBSERVER_INTERFACE_H