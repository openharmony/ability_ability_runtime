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

#ifndef MOCK_SESSION_MANAGER_LITE_H
#define MOCK_SESSION_MANAGER_LITE_H
#include "refbase.h"
#include "wm_common.h"

namespace OHOS::Rosen {
enum class WSError : int32_t {
    WS_OK = 0,
    WS_DO_NOTHING,
    WS_ERROR_NO_MEM,
    WS_ERROR_DESTROYED_OBJECT,
    WS_ERROR_INVALID_WINDOW,
    WS_ERROR_INVALID_WINDOW_MODE_OR_SIZE,
    WS_ERROR_INVALID_OPERATION,
    WS_ERROR_INVALID_PERMISSION,
    WS_ERROR_NOT_SYSTEM_APP,
    WS_ERROR_NO_REMOTE_ANIMATION,
    WS_ERROR_INVALID_DISPLAY,
    WS_ERROR_INVALID_PARENT,
    WS_ERROR_OPER_FULLSCREEN_FAILED,
    WS_ERROR_REPEAT_OPERATION,
    WS_ERROR_INVALID_SESSION,
    WS_ERROR_INVALID_CALLING,
    WS_ERROR_UNCLEARABLE_SESSION,
    WS_ERROR_FAIL_TO_GET_SNAPSHOT,
    WS_ERROR_INTERNAL_ERROR,
    WS_ERROR_NO_UI_CONTENT_ERROR,

    WS_ERROR_DEVICE_NOT_SUPPORT = 801,  // the value do not change.It is defined on all system

    WS_ERROR_NEED_REPORT_BASE = 1000,  // error code > 1000 means need report
    WS_ERROR_NULLPTR,
    WS_ERROR_INVALID_TYPE,
    WS_ERROR_INVALID_PARAM,
    WS_ERROR_SAMGR,
    WS_ERROR_IPC_FAILED,
    WS_ERROR_NEED_REPORT_END,
    WS_ERROR_START_ABILITY_FAILED,
    WS_ERROR_SET_SESSION_LABEL_FAILED,
    WS_ERROR_SET_SESSION_ICON_FAILED,
    WS_ERROR_INVALID_SESSION_LISTENER,
    WS_ERROR_START_UI_EXTENSION_ABILITY_FAILED,
    WS_ERROR_MIN_UI_EXTENSION_ABILITY_FAILED,
    WS_ERROR_TERMINATE_UI_EXTENSION_ABILITY_FAILED,
    WS_ERROR_PRE_HANDLE_COLLABORATOR_FAILED,
    WS_ERROR_START_UI_ABILITY_TIMEOUT,

    WS_ERROR_EDM_CONTROLLED = 2097215,  // enterprise limit
};

class SceneSessionManagerLite {
public:
    WSError GetRecentMainSessionInfoList(std::vector<RecentSessionInfo> &recentSessionInfoList);
    std::vector<RecentSessionInfo> recentSessionInfoList_;
};

class SessionManagerLite {
public:
    static SessionManagerLite &GetInstance();
    std::shared_ptr<SceneSessionManagerLite> GetSceneSessionManagerLiteProxy();
    std::shared_ptr<SceneSessionManagerLite> sceneSessionManagerLiteProxy_ = nullptr;
};
}  // namespace OHOS::Rosen

#endif  // MOCK_SESSION_MANAGER_LITE_H
