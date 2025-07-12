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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_UTIL_H
#define OHOS_ABILITY_RUNTIME_ABILITY_UTIL_H

#include "bundle_mgr_helper.h"
#include "hilog_tag_wrapper.h"
#include "mock_my_status.h"

namespace OHOS {
namespace AAFwk {
namespace AbilityUtil {

#define CHECK_POINTER_AND_RETURN(object, value)                \
    if (!object) {                                             \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "nullptr"); \
        return value;                                          \
    }

#define CHECK_TRUE_RETURN_RET(object, value, log)          \
    if (object) {                                          \
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s", log); \
        return value;                                      \
    }

[[maybe_unused]] static std::shared_ptr<AppExecFwk::BundleMgrHelper> GetBundleManagerHelper()
{
    return MyStatus::GetInstance().bundleMgrHelper_;
}
}  // namespace AbilityUtil
}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_ABILITY_UTIL_H
