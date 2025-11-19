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

#ifndef OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_EXECUTE_CALLBACK_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_EXECUTE_CALLBACK_INTERFACE_H

#include "iremote_broker.h"

namespace OHOS {
namespace AAFwk {

class IPreloadUIExtensionExecuteCallback : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.AAFwk.PreloadUIExtensionCallback");

    virtual void OnLoadedDone(int32_t extensionAbilityId) = 0;
    virtual void OnDestroyDone(int32_t extensionAbilityId) = 0;
    virtual void OnPreloadSuccess(int32_t requestCode, int32_t extensionAbilityId, int32_t innerErrCode) = 0;

    enum {
        ON_PRELOAD_UI_EXTENSION_ABILITY_LOADED_DONE = 1,
        ON_PRELOAD_UI_EXTENSION_ABILITY_DESTROY_DONE = 2,
        ON_PRELOAD_UI_EXTENSION_ABILITY_SUCCESS = 3,
    };
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_EXECUTE_CALLBACK_INTERFACE_H
