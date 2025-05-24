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

#ifndef OHOS_ABILITY_RUNTIME_APP_SERVICE_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_APP_SERVICE_EXTENSION_CONTEXT_H

#include "extension_context.h"
#include "ability_connect_callback.h"
#include "connection_manager.h"
#include "free_install_observer_interface.h"
#include "local_call_container.h"
#include "start_options.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @brief context supply for service
 *
 */
class AppServiceExtensionContext : public ExtensionContext {
public:
    AppServiceExtensionContext() = default;
    virtual ~AppServiceExtensionContext() = default;

    /**
     * @brief Connects the current ability to an ability using the AbilityInfo.AbilityType.SERVICE template.
     *
     * @param want Indicates the want containing information about the ability to connect
     *
     * @param conn Indicates the callback object when the target ability is connected.
     *
     * @return Returns zero on success, others on failure.
     */
    ErrCode ConnectAbility(
        const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const;

    /**
     * @brief Disconnects the current ability from an ability.
     *
     * @param conn Indicates the IAbilityConnection callback object passed by connectAbility after the connection
     * is set up. The IAbilityConnection object uniquely identifies a connection between two abilities.
     *
     * @return errCode ERR_OK on success, others on failure.
     */
    ErrCode DisconnectAbility(const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback,
        int32_t accountId = -1) const;

    /**
     * @brief Destroys the current ability.
     *
     * @return errCode ERR_OK on success, others on failure.
     */
    ErrCode TerminateSelf();
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_SERVICE_EXTENSION_CONTEXT_H