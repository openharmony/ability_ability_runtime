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

#include "window_pid_visibility_changed_listener.h"

#include "app_mgr_service_inner.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
#ifdef SUPPORT_SCREEN
using namespace OHOS::Rosen;
WindowPidVisibilityChangedListener::WindowPidVisibilityChangedListener(
    const std::weak_ptr<AppMgrServiceInner> &appInner, const std::shared_ptr<AAFwk::TaskHandlerWrap> &handler)
    : appServiceInner_(appInner), taskHandler_(handler)
{}

void WindowPidVisibilityChangedListener::NotifyWindowPidVisibilityChanged(
    const sptr<WindowPidVisibilityInfo>& windowPidVisibilityInfo)
{
    if (!windowPidVisibilityInfo) {
        TAG_LOGW(AAFwkTag::APPMGR, "Window pid visibility info is empty.");
        return;
    }

    TAG_LOGI(AAFwkTag::APPMGR, "NotifyWindowPidVisibilityChanged called, pid:%{public}d, visibilityState:%{public}d.",
        windowPidVisibilityInfo->pid_, static_cast<uint32_t>(windowPidVisibilityInfo->visibilityState_));

    if (taskHandler_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "Task handler is nullptr.");
        return;
    }

    auto task = [inner = appServiceInner_, windowPidVisibilityInfo] {
        auto serviceInner = inner.lock();
        if (serviceInner == nullptr) {
            TAG_LOGE(AAFwkTag::APPMGR, "Failed to get app mgr service inner.");
            return;
        }
        serviceInner->HandleWindowPidVisibilityChanged(windowPidVisibilityInfo);
    };
    taskHandler_->SubmitTask(task, "NotifyWindowPidVisibilityChanged");
}
#endif // SUPPORT_SCREEN
} // namespace AppExecFwk
} // namespace OHOS
