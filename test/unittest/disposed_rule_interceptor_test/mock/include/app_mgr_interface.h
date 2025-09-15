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

#ifndef OHOS_ABILITY_RUNTIME_APP_MGR_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_APP_MGR_INTERFACE_H

#include <vector>

#include "iapplication_state_observer.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {
class IAppMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.AppMgr");

    /**
     * Register application or process state observer.
     * @param observer, ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RegisterApplicationStateObserver(const sptr<IApplicationStateObserver> &observer,
        const std::vector<std::string> &bundleNameList = {}) = 0;

    /**
     * Unregister application or process state observer.
     * @param observer, ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver> &observer) = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_MGR_INTERFACE_H
