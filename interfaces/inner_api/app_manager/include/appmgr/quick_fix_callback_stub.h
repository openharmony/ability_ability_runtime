/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_QUICK_FIX_CALLBACK_STUB_H
#define OHOS_ABILITY_RUNTIME_QUICK_FIX_CALLBACK_STUB_H

#include <map>

#include "iquick_fix_callback.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixCallbackStub : public IRemoteStub<IQuickFixCallback> {
public:
    QuickFixCallbackStub();
    virtual ~QuickFixCallbackStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t HandleOnLoadPatchDoneInner(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnUnloadPatchDoneInner(MessageParcel &data, MessageParcel &reply);
    int32_t HandleOnReloadPageDoneInner(MessageParcel &data, MessageParcel &reply);

    DISALLOW_COPY_AND_MOVE(QuickFixCallbackStub);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_QUICK_FIX_CALLBACK_STUB_H
