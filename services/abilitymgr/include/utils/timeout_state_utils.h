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

#ifndef OHOS_ABILITY_RUNTIME_TIMEOUT_STATE_UTILS_H
#define OHOS_ABILITY_RUNTIME_TIMEOUT_STATE_UTILS_H

#include "freeze_util.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class TimeoutStateUtils
 * provides state utilities.
 */
class TimeoutStateUtils final {
public:
    /**
     * MsgId2FreezeTimeOutState, convert ability timeout msgid to freeze timeout state.
     *
     * @param msgId ability timeout msgid.
     * @return The freeze timeout state.
     */
    static AbilityRuntime::FreezeUtil::TimeoutState MsgId2FreezeTimeOutState(uint32_t msgId);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif //OHOS_ABILITY_RUNTIME_TIMEOUE_STATE_UTILS_H
 