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

#ifndef OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_EXTENSION_UTIL_H
#define OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_EXTENSION_UTIL_H

#include "ani.h"
#include "view_data.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
struct FillResponse {
    AbilityBase::ViewData viewData;
};

struct PopupSize {
    int32_t width = 0;
    int32_t height = 0;
};

enum AutoFillCommand {
    NONE,
    FILL,
    SAVE,
    UPDATE,
    RESIZE,
    INPUT,
    RELOAD_IN_MODAL
};

struct CustomData {
    AAFwk::WantParams data;
};

class EtsAutoFillExtensionUtil {
public:
    static ani_object WrapFillRequest(ani_env *env, const AAFwk::Want &want);
    static ani_object WrapSaveRequest(ani_env *env, const AAFwk::Want &want);
    static ani_object WrapUpdateRequest(ani_env *env, const AAFwk::WantParams &wantParams);
    static ani_object WrapViewData(ani_env *env, const AbilityBase::ViewData &viewData);
    static ani_object WrapPageNodeInfo(ani_env *env, const AbilityBase::PageNodeInfo &pageNodeInfo);
    static ani_object WrapRectData(ani_env *env, const AbilityBase::Rect &rect);
    static ani_object WrapCustomData(ani_env *env, const AAFwk::WantParams &param);
    static void UnwrapViewData(ani_env *env, const ani_object object, AbilityBase::ViewData &viewData);
    static void UnwrapPageNodeInfo(ani_env *env, const ani_object object, AbilityBase::PageNodeInfo &node);
    static void UnwrapRectData(ani_env *env, const ani_object object, AbilityBase::Rect &rect);
    static void UnwrapFillResponse(ani_env *env, const ani_object object, FillResponse &response);
    static void UnwrapPopupSize(ani_env *env, const ani_object object, PopupSize &popupSize);

    enum AutoFillResultCode {
        CALLBACK_SUCESS = 0,
        CALLBACK_FAILED,
        CALLBACK_CANCEL,
        CALLBACK_REMOVE_TIME_OUT,
        CALLBACK_FAILED_INVALID_PARAM,
    };

private:
    static bool CreateObject(ani_env *env, ani_object &object, const std::string &className);
    static ani_object SetFillRequest(ani_env *env, ani_object object, const AAFwk::Want &want);
    static ani_object SetSaveRequest(ani_env *env, ani_object object, const AAFwk::Want &want);
    static ani_object SetViewData(ani_env *env, ani_object object, const AbilityBase::ViewData &viewData);
    static void SetViewDataArray(ani_env *env, ani_object &object, const AbilityBase::ViewData &viewData);
    static ani_object SetPageNodeInfo(ani_env *env, ani_object object, const AbilityBase::PageNodeInfo &pageNodeInfo);
    static ani_object SetRectData(ani_env *env, ani_object object, const AbilityBase::Rect &rect);
    static void UnwrapViewDataString(ani_env *env, const ani_object object, AbilityBase::ViewData &viewData);
    static void UnwrapViewDataBoolean(ani_env *env, const ani_object object, AbilityBase::ViewData &viewData);
    static void UnwrapPageNodeInfoString(ani_env *env, const ani_object object, AbilityBase::PageNodeInfo &node);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_EXTENSION_UTIL_H