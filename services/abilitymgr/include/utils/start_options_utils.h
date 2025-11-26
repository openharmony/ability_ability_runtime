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

#ifndef OHOS_ABILITY_RUNTIME_START_OPTIONS_UTILS_H
#define OHOS_ABILITY_RUNTIME_START_OPTIONS_UTILS_H

#include <cstdint>

#include "refbase.h"

namespace OHOS {
class IRemoteObject;
namespace AAFwk {
class Want;
class StartOptions;

/**
* @class StartOptionsUtils
* provides start options utilities.
*/
class StartOptionsUtils final {
public:
    StartOptionsUtils() = default;
    ~StartOptionsUtils() = default;

    static int32_t CheckProcessOptions(const Want &want, const StartOptions &options, sptr<IRemoteObject> callerToken,
        int32_t userId);

private:
    static int32_t CheckProcessOptionsInner(const Want &want, const StartOptions &options,
        sptr<IRemoteObject> callerToken, int32_t userId);

    static int32_t CheckStartSelfUIAbilityStartOptions(const Want &want, const StartOptions &options);
};
}
}
#endif //OHOS_ABILITY_RUNTIME_START_OPTIONS_UTILS_H