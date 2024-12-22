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

#ifndef OHOS_ABILITY_RUNTIME_QUERY_ERMS_OBSERVER_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_QUERY_ERMS_OBSERVER_INTERFACE_H

#include <string>
#include "iremote_broker.h"

namespace OHOS {
namespace AbilityRuntime {
struct AtomicServiceStartupRule {
    bool isOpenAllowed = false;
    bool isEmbeddedAllowed = false;
};

class IQueryERMSObserver : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.IQueryERMSObserver");

    /**
     * OnQueryFinished, return free install result.
     *
     * @param appId Query ERMS app id.
     * @param startTime Free install start request time.
     * @param rule The ERMS query result.
     * @param resultCode The result code.
     */
    virtual void OnQueryFinished(const std::string &appId, const std::string &startTime,
        const AtomicServiceStartupRule &rule, int resultCode) = 0;

    enum {
        ON_QUERY_FINISHED = 1,
    };
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_QUERY_ERMS_OBSERVER_INTERFACE_H