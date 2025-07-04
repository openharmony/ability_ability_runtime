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

#include "session_manager_lite.h"

namespace OHOS::Rosen {

WSError SceneSessionManagerLite::GetRecentMainSessionInfoList(std::vector<RecentSessionInfo> &recentSessionInfoList)
{
    recentSessionInfoList = recentSessionInfoList_;
    return WSError::WS_OK;
}

SessionManagerLite &SessionManagerLite::GetInstance()
{
    static SessionManagerLite instance_;
    return instance_;
}

std::shared_ptr<SceneSessionManagerLite> SessionManagerLite::GetSceneSessionManagerLiteProxy()
{
    return sceneSessionManagerLiteProxy_;
}

}  // namespace OHOS::Rosen
