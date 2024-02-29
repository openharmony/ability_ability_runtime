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

#include "js_embedded_ui_extension.h"

#include "hilog_wrapper.h"
#include "hitrace_meter.h"
#include "js_ui_extension_base.h"

namespace OHOS {
namespace AbilityRuntime {
JsEmbeddedUIExtension *JsEmbeddedUIExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    return new JsEmbeddedUIExtension(runtime);
}

JsEmbeddedUIExtension::JsEmbeddedUIExtension(const std::unique_ptr<Runtime> &runtime)
{
    jsUIExtensionBase_ = std::make_shared<JsUIExtensionBase>(runtime);
}

JsEmbeddedUIExtension::~JsEmbeddedUIExtension()
{
    HILOG_DEBUG("destructor.");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }
}

void JsEmbeddedUIExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HILOG_DEBUG("called.");
    EmbeddedUIExtension::Init(record, application, handler, token);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->SetAbilityInfo(abilityInfo_);
    jsUIExtensionBase_->SetContext(GetContext());
    auto extensionCommon = jsUIExtensionBase_->Init(record, application, handler, token);
    SetExtensionCommon(extensionCommon);
}

void JsEmbeddedUIExtension::OnStart(const AAFwk::Want &want)
{
    HILOG_DEBUG("called.");
    Extension::OnStart(want);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->OnStart(want);
}

void JsEmbeddedUIExtension::OnStop()
{
    HILOG_DEBUG("called.");
    EmbeddedUIExtension::OnStop();

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->OnStop();
}

void JsEmbeddedUIExtension::OnCommandWindow(
    const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo, AAFwk::WindowCommand winCmd)
{
    HILOG_DEBUG("begin. persistentId: %{private}d, winCmd: %{public}d", sessionInfo->persistentId, winCmd);
    if (sessionInfo == nullptr) {
        HILOG_ERROR("sessionInfo is nullptr.");
        return;
    }
    Extension::OnCommandWindow(want, sessionInfo, winCmd);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->OnCommandWindow(want, sessionInfo, winCmd);
}

void JsEmbeddedUIExtension::OnCommand(const AAFwk::Want &want, bool restart, int32_t startId)
{
    Extension::OnCommand(want, restart, startId);
    HILOG_DEBUG("begin restart = %{public}s, startId = %{public}d.", restart ? "true" : "false", startId);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->OnCommand(want, restart, startId);
}

void JsEmbeddedUIExtension::OnForeground(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    HILOG_DEBUG("called.");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    Extension::OnForeground(want, sessionInfo);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->OnForeground(want, sessionInfo);
}

void JsEmbeddedUIExtension::OnBackground()
{
    HILOG_DEBUG("called.");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->OnBackground();
    Extension::OnBackground();
}

void JsEmbeddedUIExtension::OnConfigurationUpdated(const AppExecFwk::Configuration &configuration)
{
    HILOG_DEBUG("called.");
    Extension::OnConfigurationUpdated(configuration);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->OnConfigurationUpdated(configuration);
}

void JsEmbeddedUIExtension::Dump(const std::vector<std::string> &params, std::vector<std::string> &info)
{
    HILOG_DEBUG("called.");
    Extension::Dump(params, info);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is nullptr");
        return;
    }
    jsUIExtensionBase_->Dump(params, info);
}

void JsEmbeddedUIExtension::OnAbilityResult(int32_t requestCode, int32_t resultCode, const Want &resultData)
{
    HILOG_DEBUG("OnAbilityResult called.");
    Extension::OnAbilityResult(requestCode, resultCode, resultData);

    if (jsUIExtensionBase_ == nullptr) {
        HILOG_ERROR("jsUIExtensionBase_ is null");
        return;
    }
    jsUIExtensionBase_->OnAbilityResult(requestCode, resultCode, resultData);
}
} // namespace AbilityRuntime
} // namespace OHOS