/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_MODULE_PROFILE_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_MODULE_PROFILE_H

#include "appexecfwk_errors.h"
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class ModuleProfile {
public:
    /**
     * @brief Transform the information of module.json to InnerBundleInfo object.
     * @param buf Indicates the std::ostringstream of module.json.
     * @param innerBundleInfo Indicates the obtained InnerBundleInfo object.
     * @return Returns ERR_OK if the information transformed successfully; returns error code otherwise.
     */
    ErrCode TransformTo(const std::vector<uint8_t> &buf, InnerBundleInfo &innerBundleInfo) const;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_MODULE_PROFILE_H
