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

#ifndef OHOS_ABILITY_RUNTIME_SA_INTERCEPTOR_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_SA_INTERCEPTOR_INTERFACE_H

#include <iremote_broker.h>

#include "rule.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class ISAInterceptor
 * Interceptor is used to interceptor by SA
 */
class ISAInterceptor : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.AbilityRuntime.ISAInterceptor");

    /**
     * Execute interception processing.
     */
    virtual int32_t OnCheckStarting(const std::string &params, Rule &rule) = 0;

    enum class SAInterceptorCmd {
        // ipc id for OnCheckStarting
        ON_DO_CHECK_STARTING = 1,
        CODE_MAX
    };
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SA_INTERCEPTOR_INTERFACE_H