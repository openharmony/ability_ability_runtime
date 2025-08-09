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

#include "ets_auto_save_request_callback.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AutoFillManagerEts {
namespace {
const std::string METHOD_ON_SAVE_REQUEST_SUCCESS = "onSuccess";
const std::string METHOD_ON_SAVE_REQUEST_FAILED = "onFailure";
} // namespace

EtsAutoSaveRequestCallback::EtsAutoSaveRequestCallback(ani_vm *vm, int32_t instanceId,
    AutoFillManagerFunc autoFillManagerFunc)
    : vm_(vm), instanceId_(instanceId), autoFillManagerFunc_(autoFillManagerFunc) {}

EtsAutoSaveRequestCallback::~EtsAutoSaveRequestCallback() {}

void EtsAutoSaveRequestCallback::OnSaveRequestSuccess()
{
    TAG_LOGD(AAFwkTag::AUTOFILLMGR, "onSuccess called");
    ETSCallFunction(METHOD_ON_SAVE_REQUEST_SUCCESS);
    if (autoFillManagerFunc_ != nullptr) {
        autoFillManagerFunc_(instanceId_);
    }
}

void EtsAutoSaveRequestCallback::OnSaveRequestFailed()
{
    TAG_LOGD(AAFwkTag::AUTOFILLMGR, "onFailure called");
    ETSCallFunction(METHOD_ON_SAVE_REQUEST_FAILED);
    if (autoFillManagerFunc_ != nullptr) {
        autoFillManagerFunc_(instanceId_);
    }
}

void EtsAutoSaveRequestCallback::Register(ani_object object)
{
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null env");
        return;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null object");
        return;
    }

    if (IsEtsCallbackEquals(callback_, object)) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "callback exist");
        return;
    }

    callback_ = std::make_shared<AppExecFwk::ETSNativeReference>();
    if (callback_ == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null callback_");
        return;
    }

    ani_ref objRef = nullptr;
    ani_status status = ANI_ERROR;
    status = env->GlobalReference_Create(object, &objRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "GlobalReference_Create failed status: %{public}d", status);
        return;
    }

    callback_->aniObj = object;
    callback_->aniRef = objRef;
}

void EtsAutoSaveRequestCallback::ETSCallFunction(const std::string &methodName)
{
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null env");
        return;
    }
    if (callback_ == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null callback_");
        return;
    }

    ani_status status = ANI_OK;
    status = env->Object_CallMethodByName_Void(reinterpret_cast<ani_object>(callback_->aniRef), methodName.c_str(),
        nullptr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "Object_CallMethodByName_Void failed, status: %{public}d", status);
    }
}

bool EtsAutoSaveRequestCallback::IsEtsCallbackEquals(std::shared_ptr<AppExecFwk::ETSNativeReference> callback,
    ani_object object)
{
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "Invalid etsCallback");
        return false;
    }

    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null env");
        return false;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null object");
        return false;
    }

    ani_boolean isEquals = false;
    if ((env->Reference_StrictEquals(reinterpret_cast<ani_ref>(object), callback->aniRef, &isEquals)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "Object not match");
        return false;
    }
    
    return isEquals;
}

ani_env *EtsAutoSaveRequestCallback::GetAniEnv()
{
    TAG_LOGD(AAFwkTag::AUTOFILLMGR, "GetAniEnv call");
    if (vm_ == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null vm_");
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "GetEnv failed");
        return nullptr;
    }
    return env;
}
} // namespace AutoFillManagerEts
} // namespace OHOS