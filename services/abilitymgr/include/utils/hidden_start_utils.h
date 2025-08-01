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

#ifndef OHOS_ABILITY_RUNTIME_HIDDEN_START_UTILS_H
#define OHOS_ABILITY_RUNTIME_HIDDEN_START_UTILS_H

#include "want.h"
#include "start_options.h"

namespace OHOS {
namespace AAFwk {
/**
* @class HiddenStartUtils
* provides hidden start utilities.
*/

class HiddenStartUtils final {
public:
    static bool IsHiddenStart(const StartOptions &options);

    static int32_t CheckHiddenStartSupported(const StartOptions &options);
};
}
}
#endif //OHOS_ABILITY_RUNTIME_HIDDEN_START_UTILS_H