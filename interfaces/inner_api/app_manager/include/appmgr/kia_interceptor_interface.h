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

#ifndef OHOS_ABILITY_RUNTIME_KIA_INTERCEPTOR_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_KIA_INTERCEPTOR_INTERFACE_H

#include <iremote_broker.h>

#include "want.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class IKiaInterceptor
 * IPC interface for KIA.
 */
class IKiaInterceptor : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.IKiaInterceptor");

    /**
     * OnIntercept, processing method from KIA.
     *
     * @param want The param of openning the app.
     * @return Error code of calling the function.
     */
    virtual int OnIntercept(AAFwk::Want &want) = 0;

    enum {
        // ipc code for calling OnIntercept
        KIA_INTERCEPTOR_ON_INTERCEPT = 0,
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_KIA_INTERCEPTOR_INTERFACE_H
