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

#ifndef OHOS_ABILITY_RUNTIME_NATIVE_CHILD_NOTIFY_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_NATIVE_CHILD_NOTIFY_INTERFACE_H

#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {

class INativeChildNotify : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.NativeChildNotify");

    /**
     * Notify native child process started.
     *
     * @param nativeChild child process ipc object
     */
    virtual void OnNativeChildStarted(const sptr<IRemoteObject> &nativeChild) = 0;

    /**
     * Notify native child process start failed.
     *
     * @param errCode failed error code
     */
    virtual void OnError(int32_t errCode) = 0;

protected:
    static constexpr uint32_t IPC_ID_ON_NATIVE_CHILD_STARTED = 0;
    static constexpr uint32_t IPC_ID_ON_ERROR = 1;
};

} // OHOS
} // AppExecFwk

#endif // OHOS_ABILITY_RUNTIME_NATIVE_CHILD_NOTIFY_INTERFACE_H