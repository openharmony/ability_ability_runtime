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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_UTIL_H
#define OHOS_ABILITY_RUNTIME_ABILITY_UTIL_H

#include <string>
#include <unordered_set>

#include "bundle_mgr_helper.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "permission_verification.h"

namespace OHOS {
namespace AAFwk {
namespace AbilityUtil {
#define CHECK_POINTER_CONTINUE(object)                         \
    if (!object) {                                             \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "object nullptr"); \
        continue;                                              \
    }

#define CHECK_POINTER_IS_NULLPTR(object)                       \
    if (object == nullptr) {                                   \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "object nullptr"); \
        return;                                                \
    }

#define CHECK_POINTER(object)                                  \
    if (!object) {                                             \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "object nullptr"); \
        return;                                                \
    }

#define CHECK_POINTER_LOG(object, log)                      \
    if (!object) {                                          \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "nullptr %{public}s:", log); \
        return;                                             \
    }

#define CHECK_POINTER_TAG_LOG(object, tag, log)             \
    if (!object) {                                          \
        TAG_LOGE(tag, "%{public}s:", log);                  \
        return;                                             \
    }

#define CHECK_POINTER_AND_RETURN(object, value)                \
    if (!object) {                                             \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "object nullptr"); \
        return value;                                          \
    }

#define CHECK_POINTER_AND_RETURN_LOG(object, value, log)    \
    if (!object) {                                          \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "nullptr %{public}s:", log); \
        return value;                                       \
    }

#define CHECK_POINTER_RETURN_BOOL(object)                      \
    if (!object) {                                             \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "object nullptr"); \
        return false;                                          \
    }

#define CHECK_RET_RETURN_RET(object, log)                                            \
    if (object != ERR_OK) {                                                          \
        TAG_LOGE(AAFwkTag::ABILITYMGR, "%{public}s, ret : %{public}d", log, object); \
        return object;                                                               \
    }

#define CHECK_TRUE_RETURN_RET(object, value, log)          \
    if (object) {                                          \
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s", log); \
        return value;                                      \
    }

[[maybe_unused]] static std::shared_ptr<AppExecFwk::BundleMgrHelper> GetBundleManagerHelper()
{
    return DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
}
}  // namespace AbilityUtil
}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_ABILITY_UTIL_H
