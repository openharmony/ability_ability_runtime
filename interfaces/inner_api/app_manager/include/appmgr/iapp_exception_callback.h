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

#ifndef OHOS_ABILITY_RUNTIME_I_APP_EXCEPTION_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_I_APP_EXCEPTION_CALLBACK_H

#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
enum class LifecycleException {
    LAUNCH_ABILITY_FAIL,
    FOREGROUND_APP_FAIL,
    FOREGROUND_APP_WAIT,
    END
};

class IAppExceptionCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.AppExceptionCallback");

    /**
     * Notify abilityManager lifecycle exception.
     *
     * @param type lifecycle failed type
     * @param token associated ability
     */
    virtual void OnLifecycleException(LifecycleException type, sptr<IRemoteObject> token) {}

    enum class Message {
        LIFECYCLE_EXCEPTION_MSG_ID = 0,
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_I_APP_EXCEPTION_CALLBACK_H
