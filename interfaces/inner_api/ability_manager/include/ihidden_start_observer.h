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

#ifndef OHOS_ABILITY_RUNTIME_IHIDDEN_START_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_IHIDDEN_START_OBSERVER_H

#include <string>
#include "iremote_object.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AAFwk {
class IHiddenStartObserver : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.IHiddenStartObserver");

    /**
     * IsHiddenStart, return if the given app is started hidden.
     *
     * @param uid Uid of the given app.
     * @return if the given app is started hidden
     */
    virtual bool IsHiddenStart(int32_t uid) = 0;

    enum class Message {
        TRANSACT_ON_IS_HIDDEN_START = 0,
    };
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_IHIDDEN_START_OBSERVER_H