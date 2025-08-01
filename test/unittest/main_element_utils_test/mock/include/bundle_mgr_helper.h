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

#ifndef OHOS_ABILITY_RUNTIME_BUNDLE_MGR_HELPER_H
#define OHOS_ABILITY_RUNTIME_BUNDLE_MGR_HELPER_H

#include <memory>

#include "ability_info.h"
#include "bundle_info.h"
#include "want.h"

namespace OHOS {

namespace AppExecFwk {
class BundleMgrHelper {
public:
    BundleMgrHelper();

    ~BundleMgrHelper();

    static std::shared_ptr<BundleMgrHelper> GetInstance();

    ErrCode GetBundleInfoV9(
        const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_BUNDLE_MGR_HELPER_H