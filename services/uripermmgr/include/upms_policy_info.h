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

#ifndef ABILITY_ABILITY_RUNTIME_UPMS_POLICY_INFO_H
#define ABILITY_ABILITY_RUNTIME_UPMS_POLICY_INFO_H

#include <sys/types.h>
#include <string>

namespace OHOS {
namespace AAFwk {
struct PolicyInfo final {
    std::string path;
    uint64_t mode;
};

} // namespace AAFwk
} // namespace OHOS
#endif // ABILITY_ABILITY_RUNTIME_UPMS_POLICY_INFO_H