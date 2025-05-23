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

#include "js_app_process_state.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
JsAppProcessState ConvertToJsAppProcessState(AppExecFwk::AppProcessState appProcessState, bool isFocused)
{
    JsAppProcessState processState;
    switch (appProcessState) {
        case AppExecFwk::AppProcessState::APP_STATE_CREATE:
        case AppExecFwk::AppProcessState::APP_STATE_READY:
            processState = STATE_CREATE;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_FOREGROUND:
            processState = isFocused ? STATE_ACTIVE : STATE_FOREGROUND;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_BACKGROUND:
            processState = STATE_BACKGROUND;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_TERMINATED:
        case AppExecFwk::AppProcessState::APP_STATE_END:
            processState = STATE_DESTROY;
            break;
        default:
            TAG_LOGE(AAFwkTag::APPMGR, "invalid state");
            processState = STATE_DESTROY;
            break;
    }
    return processState;
}
} // namespace AbilityRuntime
} // namespace OHOS