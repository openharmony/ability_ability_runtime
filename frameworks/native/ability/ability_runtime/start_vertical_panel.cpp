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
#include "start_vertical_panel.h"

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "string_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#endif // SUPPORT_SCREEN

namespace OHOS {
namespace AbilityRuntime {
#ifdef SUPPORT_SCREEN
constexpr const char* UIEXTENSION_TARGET_TYPE_KEY = "ability.want.params.uiExtensionTargetType";
constexpr const char* FLAG_AUTH_READ_URI_PERMISSION = "ability.want.params.uriPermissionFlag";
constexpr const char* SCREENCONFIG_SCREENMODE = "ohos.verticalpanel.screenconfig.screenmode";
constexpr const char* SCREENCONFIG_BUNDLENAME = "ohos.verticalpanel.screenconfig.bundlename";
constexpr const char* SCREENCONFIG_MODULENAME = "ohos.verticalpanel.screenconfig.modulename";
constexpr const char* SCREENCONFIG_ABILITYNAME = "ohos.verticalpanel.screenconfig.abilityname";
constexpr const char* SCREENCONFIG_WINDOWID = "ohos.verticalpanel.screenconfig.windowid";
constexpr const char* SCREENMODE = "screenMode";
constexpr const char* BUNDLENAME = "bundleName";
constexpr const char* MODULENAME = "moduleName";
constexpr const char* ABILITYNAME = "abilityName";
constexpr const char* WINDOWID = "windowId";

bool SetParamsForWantParams(AAFwk::WantParams &wantParams, const AAFwk::ScreenConfig &screenConfig)
{
    auto iter = screenConfig.sourceAppInfo.find(SCREENMODE);
    if (iter == screenConfig.sourceAppInfo.end()) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "ohos.verticalpanel.screenconfig.screenmode is not exist");
        return false;
    }
    wantParams.SetParam(SCREENCONFIG_SCREENMODE, AAFwk::String::Box(iter->second));

    iter = screenConfig.sourceAppInfo.find(BUNDLENAME);
    if (iter == screenConfig.sourceAppInfo.end()) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "ohos.verticalpanel.screenconfig.bundlename is not exist");
        return false;
    }
    wantParams.SetParam(SCREENCONFIG_BUNDLENAME, AAFwk::String::Box(iter->second));

    iter = screenConfig.sourceAppInfo.find(MODULENAME);
    if (iter == screenConfig.sourceAppInfo.end()) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "ohos.verticalpanel.screenconfig.modulename is not exist");
        return false;
    }
    wantParams.SetParam(SCREENCONFIG_MODULENAME, AAFwk::String::Box(iter->second));

    iter = screenConfig.sourceAppInfo.find(ABILITYNAME);
    if (iter == screenConfig.sourceAppInfo.end()) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "ohos.verticalpanel.screenconfig.abilityname is not exist");
        return false;
    }
    wantParams.SetParam(SCREENCONFIG_ABILITYNAME, AAFwk::String::Box(iter->second));

    iter = screenConfig.sourceAppInfo.find(WINDOWID);
    if (iter == screenConfig.sourceAppInfo.end()) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "ohos.verticalpanel.screenconfig.windowId is not exist");
        return false;
    }
    wantParams.SetParam(SCREENCONFIG_WINDOWID, AAFwk::String::Box(iter->second));
    return true;
}

ErrCode StartVerticalPanel(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> context,
    AAFwk::WantParams &wantParams,
    const AAFwk::ScreenConfig &screenConfig,
    std::shared_ptr<PanelStartCallback> panelStartCallback)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "StartVerticalPanel call");
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "StartVerticalPanel null content");
        return ERR_INVALID_VALUE;
    }
    auto uiContent = context->GetUIContent();
    if (uiContent == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "StartVerticalPanel null uiContent");
        return AAFwk::ERR_MAIN_WINDOW_NOT_EXIST;
    }
    wantParams.SetParam(UIEXTENSION_TARGET_TYPE_KEY, AAFwk::String::Box(screenConfig.type));
    if (!SetParamsForWantParams(wantParams, screenConfig)) {
        return ERR_INVALID_VALUE;
    }
    AAFwk::Want want;
    want.SetParams(wantParams);
    if (wantParams.HasParam(FLAG_AUTH_READ_URI_PERMISSION)) {
        int32_t flag = wantParams.GetIntParam(FLAG_AUTH_READ_URI_PERMISSION, 0);
        want.SetFlags(flag);
        wantParams.Remove(FLAG_AUTH_READ_URI_PERMISSION);
    }
    if (panelStartCallback == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "StartVerticalPanel null panelStartCallback");
        return ERR_INVALID_VALUE;
    }
    Ace::ModalUIExtensionCallbacks callback;
    callback.onError = [panelStartCallback](int32_t arg, const std::string &str1, const std::string &str2) {
        panelStartCallback->OnError(arg);
    };
    callback.onRelease = [panelStartCallback](int32_t arg) {
        panelStartCallback->OnRelease(arg);
    };
    callback.onResult = [panelStartCallback](int32_t arg1, const OHOS::AAFwk::Want arg2) {
        panelStartCallback->OnResult(arg1, arg2);
    };
    Ace::ModalUIExtensionConfig config;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, callback, config);
    if (sessionId == 0) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "StartVerticalPanel createModalUIExtension failed");
        return ERR_INVALID_VALUE;
    }
    panelStartCallback->SetUIContent(uiContent);
    panelStartCallback->SetSessionId(sessionId);
    return ERR_OK;
}
#endif // SUPPORT_SCREEN
} // namespace AbilityRuntime
} // namespace OHOS