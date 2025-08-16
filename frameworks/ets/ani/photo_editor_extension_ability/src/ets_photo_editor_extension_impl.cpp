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

#include "ets_photo_editor_extension_impl.h"
#include "ets_ui_extension.h"
#include "ability_context.h"
#include "ability_delegator_registry.h"
#include "ability_info.h"
#include "ability_manager_client.h"
#include "ability_start_setting.h"
#include "configuration_utils.h"
#include "connection_manager.h"
#include "context.h"
#include "hitrace_meter.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_executor_info.h"
#include "insight_intent_executor_mgr.h"
#include "int_wrapper.h"
#include "ani_common_want.h"
#include "ui_extension_window_command.h"
#include "want_params_wrapper.h"
#include "ets_data_struct_converter.h"
#include "ets_ui_extension_context.h"
#include "ets_photo_editor_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;


namespace {

} // namespace

EtsPhotoEditorExtensionImpl::EtsPhotoEditorExtensionImpl(const std::unique_ptr<Runtime> &etsRuntime)
    : EtsUIExtensionBase(etsRuntime)
{
}

ani_object EtsPhotoEditorExtensionImpl::CreateETSContext(ani_env* env,
    std::shared_ptr<PhotoEditorExtensionContext> context)
{
    ani_object obj = CreateEtsPhotoEditorExtensionContext(env, context);
    return obj;
}

void EtsPhotoEditorExtensionImpl::BindContext()
{
    auto env = etsRuntime_.GetAniEnv(); // 使用base基类的etsRuntime_
   
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null Context");
        return;
    }

    TAG_LOGD(AAFwkTag::UI_EXT, "BindContext CreateJsPhotoEditorExtensionContext");
    ani_object contextObj = CreateETSContext(env, context_);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null contextObj");
        return;
    }

    ani_field contextField = nullptr;
    auto status = env->Class_FindField(etsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "BindContext::Class_FindField status : %{public}d", status);
        return;
    }
    ani_ref contextRef = nullptr;
    if ((status = env->GlobalReference_Create(contextObj, &contextRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "BindContext::GlobalReference_Create status : %{public}d", status);
        return;
    }

    if ((status = env->Object_SetField_Ref(etsObj_->aniObj, contextField, contextRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "BindContext::Object_SetField_Ref status : %{public}d", status);
        return;
    }
    shellContextRef_ = std::make_shared<AppExecFwk::ETSNativeReference>();
    shellContextRef_->aniObj = contextObj;
    shellContextRef_->aniRef = contextRef;
    context_->Bind(etsRuntime_, &(shellContextRef_->aniRef)); // 绑定aniRef指针，否则前端获取不到abilityContext
    TAG_LOGD(AAFwkTag::UI_EXT, "EtsUIExtensionBase bind etsRuntime_");

    TAG_LOGD(AAFwkTag::UI_EXT, "EtsPhotoEditorExtensionImpl::BindContext end");
}

void EtsPhotoEditorExtensionImpl::OnForeground(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    EtsUIExtensionBase::OnForeground(want, sessionInfo);
    auto componentId = sessionInfo->uiExtensionComponentId;
    if (uiExtensionComponentIdSet_.find(componentId) == uiExtensionComponentIdSet_.end()) {
        OnStartContentEditing(want, sessionInfo);
        uiExtensionComponentIdSet_.emplace(componentId);
    }
}

void EtsPhotoEditorExtensionImpl::OnStartContentEditing(const AAFwk::Want &want,
                                                       const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "EtPhotoEditorExtension want: (%{public}s), begin", want.ToUri().c_str());

    std::string imageUri = want.GetStringParam("ability.params.stream");
    if (imageUri.empty()) {
        TAG_LOGE(AAFwkTag::UI_EXT, "empty imageUri");
        return;
    }

    TAG_LOGD(AAFwkTag::UI_EXT, "EtsPhotoEditorExtension imageUri: (%{public}s), begin", imageUri.c_str());
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return;
    }
    context_->SetWant(std::make_shared<AAFwk::Want>(want));

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    ani_ref wantRef = AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniWant");
        return;
    }

    ani_string aniImageUri {};
    env->String_NewUTF8(imageUri.c_str(), imageUri.size(), &aniImageUri);
    ani_ref sessionObj = contentSessions_[sessionInfo->uiExtensionComponentId];
    if (sessionObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null sessionObj");
        return;
    }
    // c++调js,元能力封装
    CallObjectMethod(false, "onStartContentEditing", nullptr, aniImageUri, wantRef, sessionObj);

    TAG_LOGD(AAFwkTag::UI_EXT, "OnStartContentEditing End");
}
}
}