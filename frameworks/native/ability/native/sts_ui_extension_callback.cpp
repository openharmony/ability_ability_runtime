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

#include "sts_ui_extension_callback.h"

#include "ability_business_error.h"
#include "ani_common_ability_result.h"
#include "hilog_tag_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#include "ws_common.h"
#endif // SUPPORT_SCREEN

namespace OHOS {
namespace AbilityRuntime {
#ifdef SUPPORT_SCREEN
constexpr const char* ERROR_MSG_INNER = "Inner error.";
#endif // SUPPORT_SCREEN

namespace {
constexpr const char* ABILITY_START_CLASS_NAME = "Lapplication/AbilityStartCallback/AbilityStartCallback;";
}

StsUIExtensionCallback::StsUIExtensionCallback() : JsUIExtensionCallback(nullptr)
{
}

StsUIExtensionCallback::~StsUIExtensionCallback()
{
}

void StsUIExtensionCallback::SetSessionId(int32_t sessionId)
{
    aniSessionId_ = sessionId;
}

void StsUIExtensionCallback::SetUIContent(Ace::UIContent* uiContent)
{
    aniUIContent_ = uiContent;
}

void StsUIExtensionCallback::OnError(int32_t number)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    auto aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniEnv");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_class clsCall = nullptr;
    if ((status = aniEnv->FindClass(ABILITY_START_CLASS_NAME, &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "find AbilityStartCallback class failed, status : %{public}d", status);
        return;
    }
    ani_method method = nullptr;
    if ((status = aniEnv->Class_FindMethod(clsCall, "onError", "ILstd/core/String;Lstd/core/String;:V",
        &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "find onError method failed, status : %{public}d", status);
        return;
    }
    std::string name;
    std::string message;
#ifdef SUPPORT_SCREEN
    if (number != static_cast<int32_t>(Rosen::WSError::WS_OK)) {
        number = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
        name = ERROR_MSG_INNER;
        message = "StartAbilityByType failed.";
    }
#endif // SUPPORT_SCREEN
    ani_string aniName;
    if ((status = aniEnv->String_NewUTF8(name.c_str(), name.length(), &aniName)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "String_NewUTF8 failed, status : %{public}d", status);
        return;
    }
    ani_string aniMsg;
    if ((status = aniEnv->String_NewUTF8(message.c_str(), message.length(), &aniMsg)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "String_NewUTF8 failed, status : %{public}d", status);
        return;
    }
    ani_int aniCode = number;
    if ((status = aniEnv->Object_CallMethod_Void(reinterpret_cast<ani_object>(startAbilityAniCallback_),
        method, aniCode, aniName, aniMsg)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "call onError method failed, status : %{public}d", status);
        return;
    }
    CloseModalUIExtension();
}

void StsUIExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    auto aniEnv = GetAniEnv();
    if (aniEnv == nullptr || startAbilityAniCallback_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniEnv");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_object startCallback = reinterpret_cast<ani_object>(startAbilityAniCallback_);
    ani_ref onResultRef {};
    if ((status = aniEnv->Object_GetFieldByName_Ref(startCallback, "onResult", &onResultRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "get onResult failed, status : %{public}d", status);
        return;
    }
    ani_fn_object onResultFn = reinterpret_cast<ani_fn_object>(onResultRef);
    ani_object abilityResultObj = AppExecFwk::WrapAbilityResult(aniEnv, resultCode, want);
    if (abilityResultObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "create abilityResultObj failed");
        return;
    }

    ani_ref abilityResultObjRef = nullptr;
    if ((status = aniEnv->GlobalReference_Create(abilityResultObj, &abilityResultObjRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GlobalReference_Create abilityResultObj failed, status : %{public}d", status);
        return;
    }
    ani_ref argv[] = { abilityResultObjRef };
    if ((status = aniEnv->FunctionalObject_Call(onResultFn, 1, argv, nullptr)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "call onResult fn failed, status : %{public}d", status);
        return;
    }
    CloseModalUIExtension();
}

void StsUIExtensionCallback::OnRelease(int32_t code)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "call, code:%{public}d", code);
    CloseModalUIExtension();
}

void StsUIExtensionCallback::SetStsCallbackObject(ani_vm* aniVM, ani_object aniObject)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    if (aniVM == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniVM");
        return;
    }
    aniVM_ = aniVM;
    ani_env *aniEnv = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = aniVM_->GetEnv(ANI_VERSION_1, &aniEnv)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv failed, status : %{public}d", status);
        return;
    }

    ani_ref startAbilityCallbackRef = nullptr;
    if ((status = aniEnv->GlobalReference_Create(aniObject, &startAbilityCallbackRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GlobalReference_Create failed, status : %{public}d", status);
        return;
    }
    startAbilityAniCallback_ = startAbilityCallbackRef;
}

ani_env* StsUIExtensionCallback::GetAniEnv()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call");
    if (aniVM_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniVM_");
        return nullptr;
    }
    ani_env *aniEnv = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = aniVM_->GetEnv(ANI_VERSION_1, &aniEnv)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "get env failed, status : %{public}d", status);
        return nullptr;
    }
    return aniEnv;
}

void StsUIExtensionCallback::CloseModalUIExtension()
{
    if (aniUIContent_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniUIContent_");
        return;
    }
    aniUIContent_->CloseModalUIExtension(aniSessionId_);
}
}  // namespace AbilityRuntime
}  // namespace OHOS