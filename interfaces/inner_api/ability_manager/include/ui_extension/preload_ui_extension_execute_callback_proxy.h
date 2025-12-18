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

#ifndef OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_EXTENSION_CALLBACK_PROXY_H
#define OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_EXTENSION_CALLBACK_PROXY_H

#include "iremote_proxy.h"
#include "preload_ui_extension_execute_callback_interface.h"

namespace OHOS {
namespace AAFwk {
class PreloadUIExtensionExecuteCallbackProxy : public IRemoteProxy<IPreloadUIExtensionExecuteCallback> {
public:
    explicit PreloadUIExtensionExecuteCallbackProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<IPreloadUIExtensionExecuteCallback>(impl)
    {}

    virtual ~PreloadUIExtensionExecuteCallbackProxy() {}

    void OnLoadedDone(int32_t extensionAbilityId) override;
    void OnDestroyDone(int32_t extensionAbilityId) override;
    void OnPreloadSuccess(int32_t requestCode, int32_t extensionAbilityId, int32_t innerErrCode) override;

private:
    static inline BrokerDelegator<PreloadUIExtensionExecuteCallbackProxy> delegator_;
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_EXTENSION_CALLBACK_PROXY_H