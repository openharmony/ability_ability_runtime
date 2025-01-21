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
#ifndef BASE_ABILITYRUNTIME_MOCK_IQUERYERMSOBSERVER_H
#define BASE_ABILITYRUNTIME_MOCK_IQUERYERMSOBSERVER_H

#include "query_erms_observer_interface.h"

namespace OHOS {
namespace AbilityRuntime {

class IQueryERMSObserverMock : public IQueryERMSObserver {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.IQueryERMSObserver");

    void OnQueryFinished(const std::string &appId, const std::string &startTime,
                         const AtomicServiceStartupRule &rule, int resultCode)
    {
        return;
    }
    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    }
    enum {
        ON_QUERY_FINISHED = 1,
    };
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif