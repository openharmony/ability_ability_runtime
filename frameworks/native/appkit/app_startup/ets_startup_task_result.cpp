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

#include "ets_startup_task_result.h"

#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"

namespace OHOS {
namespace AbilityRuntime {
EtsStartupTaskResult::EtsStartupTaskResult() : JsStartupTaskResult()
{}

EtsStartupTaskResult::~EtsStartupTaskResult()
{
    if (resultRef_ == nullptr) {
        return;
    }
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "etsVm null");
        return;
    }
    bool isAttachThread = false;
    ani_env *aniEnv = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "aniEnv null");
        return;
    }
    ani_status status = aniEnv->GlobalReference_Delete(resultRef_);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "GlobalReference_Delete failed, status: %{public}d", status);
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

EtsStartupTaskResult::EtsStartupTaskResult(int32_t resultCode, const std::string &resultMessage)
    : JsStartupTaskResult(resultCode, resultMessage)
{}

EtsStartupTaskResult::EtsStartupTaskResult(ani_vm *etsVm, ani_object result) : JsStartupTaskResult(), etsVm_(etsVm)
{
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "etsVm null");
        return;
    }
    bool isAttachThread = false;
    ani_env *aniEnv = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "aniEnv null");
        return;
    }
    ani_status status = aniEnv->GlobalReference_Create(result, &resultRef_);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "GlobalReference_Create failed, status: %{public}d", status);
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

StartupTaskResult::ResultType EtsStartupTaskResult::GetResultType() const
{
    return ResultType::ETS;
}

ani_object EtsStartupTaskResult::JsToEtsResult(ani_env *aniEnv, std::shared_ptr<NativeReference> jsRef)
{
    TAG_LOGD(AAFwkTag::STARTUP, "JsToEtsResult");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "aniEnv null");
        return nullptr;
    }
    if (jsRef == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "jsRef null");
        return nullptr;
    }
    auto napiValue = jsRef->GetNapiValue();
    if (napiValue == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "napiValue null");
        return nullptr;
    }
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TAG_LOGE(AAFwkTag::STARTUP, "arkts_napi_scope_open failed");
        return nullptr;
    }
    hybridgref ref = nullptr;
    bool success = hybridgref_create_from_napi(napiEnv, napiValue, &ref);
    if (!success) {
        TAG_LOGE(AAFwkTag::STARTUP, "hybridgref_create_from_napi failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }
    ani_object result = nullptr;
    success = hybridgref_get_esvalue(aniEnv, ref, &result);
    if (!success) {
        TAG_LOGE(AAFwkTag::STARTUP, "hybridgref_get_esvalue failed");
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }
    ani_ref unwrapResult = nullptr;
    ani_status status = aniEnv->Object_CallMethodByName_Ref(result, "unwrap", ":C{std.core.Object}", &unwrapResult);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "Object_CallMethodByName_Ref failed: %{public}d", status);
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        return nullptr;
    }
    hybridgref_delete_from_napi(napiEnv, ref);
    arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
    return reinterpret_cast<ani_object>(unwrapResult);
}

const std::shared_ptr<NativeReference> EtsStartupTaskResult::GetJsStartupResultRef()
{
    TAG_LOGD(AAFwkTag::STARTUP, "GetJsStartupResultRef");
    if (jsStartupResultRef_ != nullptr) {
        return jsStartupResultRef_;
    }
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "etsVm null");
        return nullptr;
    }
    if (resultRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "resultRef_ null");
        return nullptr;
    }
    bool isAttachThread = false;
    ani_env *aniEnv = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "aniEnv null");
        return nullptr;
    }
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TAG_LOGE(AAFwkTag::STARTUP, "arkts_napi_scope_open failed");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return nullptr;
    }
    hybridgref ref = nullptr;
    if (!hybridgref_create_from_ani(aniEnv, resultRef_, &ref)) {
        TAG_LOGE(AAFwkTag::STARTUP, "hybridgref_create_from_ani failed");
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return nullptr;
    }
    napi_value result = nullptr;
    if (!hybridgref_get_napi_value(napiEnv, ref, &result)) {
        TAG_LOGE(AAFwkTag::STARTUP, "hybridgref_get_napi_value failed");
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return nullptr;
    }
    napi_ref resultRef = nullptr;
    napi_status status = napi_create_reference(napiEnv, result, 1, &resultRef);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::STARTUP, "napi_create_reference failed: %{public}d", status);
        hybridgref_delete_from_napi(napiEnv, ref);
        arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return nullptr;
    }
    jsStartupResultRef_ = std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference*>(resultRef));
    hybridgref_delete_from_napi(napiEnv, ref);
    arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
    return jsStartupResultRef_;
}

ani_ref EtsStartupTaskResult::GetEtsStartupResultRef() const
{
    return resultRef_;
}
} // namespace AbilityRuntime
} // namespace OHOS
