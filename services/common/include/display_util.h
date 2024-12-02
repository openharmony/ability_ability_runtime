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

#ifndef OHOS_ABILITY_RUNTIME_DISPLAY_UTIL_H
#define OHOS_ABILITY_RUNTIME_DISPLAY_UTIL_H

#include "hilog_tag_wrapper.h"
#ifdef SUPPORT_GRAPHICS
#include "display_manager.h"
#include "scene_board_judgement.h"
#endif // SUPPORT_GRAPHICS

namespace OHOS {
namespace AAFwk {
namespace DisplayUtil {
#ifdef SUPPORT_GRAPHICS
static inline int32_t GetDefaultDisplayId()
{
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetPrimaryDisplaySync();
        if (display != nullptr) {
            TAG_LOGD(AAFwkTag::DEFAULT, "displayId: %{public}d", static_cast<int32_t>(display->GetId()));
            return static_cast<int32_t>(display->GetId());
        }
    }
    return static_cast<int32_t>(Rosen::DisplayManager::GetInstance().GetDefaultDisplayId());
}
#endif
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_DISPLAY_UTIL_H