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

#include "ets_request_info.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

RequestInfo::RequestInfo(const sptr<IRemoteObject> &token, int32_t left, int32_t top, int32_t width, int32_t height)
{
    callerToken_ = token;
    left_ = left;
    top_ = top;
    width_ = width;
    height_ = height;
}

RequestInfo::~RequestInfo()
{
}

sptr<IRemoteObject> RequestInfo::GetToken()
{
    return callerToken_;
}

ani_object RequestInfo::WrapRequestInfo(ani_env *env, RequestInfo *request)
{
    TAG_LOGD(AAFwkTag::DIALOG, "call");
    if (env == nullptr || request == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null input");
        return nullptr;
    }

    ani_class cls {};
    ani_status status = env->FindClass("@ohos.app.ability.dialogRequest.dialogRequest.RequestInfoInner", &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "FindClass failed: %{public}d", status);
        return nullptr;
    }

    ani_method ctorMethod = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &ctorMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "find constructor failed: %{public}d", status);
        return nullptr;
    }
    ani_long ptr = (ani_long)(request);
    ani_object result = nullptr;
    if ((status = env->Object_New(cls, ctorMethod, &result, ptr)) != ANI_OK || result == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "Object_New failed: %{public}d", status);
        return nullptr;
    }

    ani_object windowRectObj = CreateEtsWindowRect(env, request->left_,
        request->top_, request->width_, request->height_);
    if (windowRectObj == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "CreateEtsWindowRect failed");
        return nullptr;
    }
    if ((status = env->Object_SetPropertyByName_Ref(result, "windowRect", windowRectObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "SetPropertyByName_Ref failed: %{public}d", status);
        return nullptr;
    }

    return result;
}

bool SetWindowRect(ani_env *env,
    ani_object object, int32_t left, int32_t top, int32_t width, int32_t height)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "env is null");
        return false;
    }

    ani_status status = ANI_OK;
    if ((status = env->Object_SetPropertyByName_Int(object, "left", left)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "pid failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Int(object, "top", top)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "pid failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Int(object, "width", width)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "pid failed status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Int(object, "height", height)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "pid failed status:%{public}d", status);
        return false;
    }
    return true;
}

ani_object RequestInfo::CreateEtsWindowRect(
    ani_env *env, int32_t left, int32_t top, int32_t width, int32_t height)
{
    TAG_LOGD(AAFwkTag::DIALOG, "left:%{public}d, top:%{public}d, width:%{public}d, height:%{public}d",
        left, top, width, height);
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_method method {};
    ani_object object = nullptr;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null env");
        return nullptr;
    }
    if ((status = env->FindClass("@ohos.app.ability.dialogRequest.dialogRequest.WindowRectInner", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "FindClass failed status : %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null cls");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "find ctor failed status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "Object_New failed status : %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null object");
        return nullptr;
    }
    if (!SetWindowRect(env, object, left, top, width, height)) {
        TAG_LOGE(AAFwkTag::DIALOG, "SetWindowRect failed");
        return nullptr;
    }
    return object;
}

std::shared_ptr<RequestInfo> RequestInfo::UnwrapRequestInfo(ani_env *env, ani_object etsParam)
{
    TAG_LOGI(AAFwkTag::DIALOG, "call");
    if (env == nullptr || etsParam == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "null input");
        return nullptr;
    }

    ani_class cls;
    ani_status status = env->FindClass("@ohos.app.ability.dialogRequest.RequestInfoInner", &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "FindClass failed: %{public}d", status);
        return nullptr;
    }

    ani_field nativeField = nullptr;
    if ((status = env->Class_FindField(cls, "nativeRequestInfo", &nativeField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "Class_FindField failed: %{public}d", status);
        return nullptr;
    }

    ani_long param_value = 0;
    if ((status = env->Object_GetField_Long(etsParam, nativeField, &param_value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DIALOG, "Object_GetField_Long failed: %{public}d", status);
        return nullptr;
    }

    RequestInfo *info = reinterpret_cast<RequestInfo*>(param_value);
    if (info == nullptr) {
        TAG_LOGE(AAFwkTag::DIALOG, "info null");
        return nullptr;
    }

    return std::make_shared<RequestInfo>(*info);
}

}  // namespace AbilityRuntime
}  // namespace OHOS