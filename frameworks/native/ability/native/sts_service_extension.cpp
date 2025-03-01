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

#include "sts_service_extension.h"

#include "ability_business_error.h"
#include "ability_handler.h"
#include "ability_info.h"
#include "ability_manager_client.h"
#include "configuration_utils.h"
#include "hitrace_meter.h"
#include "hilog_tag_wrapper.h"
#include "sts_runtime.h"
#include "js_runtime_utils.h"
#ifdef SUPPORT_GRAPHICS
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "window_scene.h"
#endif

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

ani_ref WrapWant(ani_env* env, const Want &want)
{
    TAG_LOGE(AAFwkTag::SERVICE_EXT, "WrapWant");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("L@ohos/app/ability/Want/Want;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantCls");
        return nullptr;
    }

    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    ani_object object = nullptr;
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null object");
        return nullptr;
    }
    ani_field field = nullptr;
    ani_string string = nullptr;
    auto elementName = want.GetElement();

    if ((status = env->Class_FindField(cls, "deviceId", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    env->String_NewUTF8(elementName.GetDeviceID().c_str(), elementName.GetDeviceID().size(), &string);
    if ((status = env->Object_SetField_Ref(object, field, string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "bundleName", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->String_NewUTF8(elementName.GetBundleName().c_str(),
        elementName.GetBundleName().size(), &string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Ref(object, field, string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    env->Class_FindField(cls, "abilityName", &field);
    env->String_NewUTF8(elementName.GetAbilityName().c_str(), elementName.GetAbilityName().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    env->Class_FindField(cls, "moduleName", &field);
    env->String_NewUTF8(elementName.GetModuleName().c_str(), elementName.GetModuleName().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    env->Class_FindField(cls, "uri", &field);
    env->String_NewUTF8(want.GetUriString().c_str(), want.GetUriString().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    env->Class_FindField(cls, "type", &field);
    env->String_NewUTF8(want.GetType().c_str(), want.GetType().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    if ((status = env->Class_FindField(cls, "flags", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Int(object, field, want.GetFlags())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }

    env->Class_FindField(cls, "action", &field);
    env->String_NewUTF8(want.GetAction().c_str(), want.GetAction().size(), &string);
    env->Object_SetField_Ref(object, field, string);

    ani_ref wantRef = nullptr;
    if ((status = env->GlobalReference_Create(object, &wantRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    return wantRef;
}

StsServiceExtension* StsServiceExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new StsServiceExtension(static_cast<STSRuntime&>(*runtime));
}

StsServiceExtension::StsServiceExtension(STSRuntime& stsRuntime) : stsRuntime_(stsRuntime)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "StsServiceExtension::StsServiceExtension");
}

StsServiceExtension::~StsServiceExtension()
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "StsServiceExtension::~StsServiceExtension");
}

void StsServiceExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "StsServiceExtension::Init");
}

void StsServiceExtension::SetAbilityContext(std::shared_ptr<AbilityInfo> abilityInfo,
    std::shared_ptr<AAFwk::Want> want, const std::string &moduleName, const std::string &srcPath)
{
}

void StsServiceExtension::OnStart(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");

    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.sts");
        return;
    }

    ani_ref wantRef = WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return;
    }

    const char* signature = "L@ohos/app/ability/Want/Want;:V";
    CallObjectMethod(false, "onCreate", signature, wantRef);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

void StsServiceExtension::OnStop()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    const char* signature = ":V";
    CallObjectMethod(false, "onDestroy", signature);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

sptr<IRemoteObject> StsServiceExtension::OnConnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.sts");
        return nullptr;
    }

    ani_ref wantRef = WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return nullptr;
    }
    const char* signature = "L@ohos/app/ability/Want/Want;:V";
    CallObjectMethod(false, "onConnect", signature, wantRef);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
    return nullptr;
}

void StsServiceExtension::OnDisconnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.sts");
        return;
    }

    ani_ref wantRef = WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return;
    }
    const char* signature  = "L@ohos/app/ability/Want/Want;:V";
    CallObjectMethod(false, "onDisconnect", signature, wantRef);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

void StsServiceExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.sts");
        return;
    }

    ani_ref wantRef = WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
    }

    ani_int iStartId = static_cast<ani_int>(startId);
    const char* signature  = "L@ohos/app/ability/Want/Want;I:V";
    CallObjectMethod(false, "onRequest", signature, wantRef, iStartId);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
    return;
}

ani_ref StsServiceExtension::CallObjectMethod(bool withResult, const char* name, const char* signature, ...)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "call sts, name: %{public}s", name);
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    auto env = stsRuntime_.GetAniEnv();
    if ((status = env->FindClass("L@ohos/app/ability/ServiceExtensionAbility/ServiceExtensionAbility;", &cls))
        != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null ServiceExtensionAbility");
        return nullptr;
    }

    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }

    ani_object object = nullptr;
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        return nullptr;
    }

    if (object == nullptr) {
        return nullptr;
    }

    if ((status = env->Class_FindMethod(cls, name, signature, &method)) != ANI_OK) {
        return nullptr;
    }

    if (method == nullptr) {
        return nullptr;
    }

    ani_ref res = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(object, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        }
        va_end(args);
        return res;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(object, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
    }
    va_end(args);
    return nullptr;
}

void StsServiceExtension::TestServiceExtension(const std::unique_ptr<Runtime>& runtime)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    StsServiceExtension* pTestServiceExtension = StsServiceExtension::Create(runtime);
    if (pTestServiceExtension == nullptr) {
        return;
    }

    Want want;
    WantParams wantParams;
    std::string paramName(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME);
    std::string insightIntentId(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_ID);
    want.SetParams(wantParams);
    AppExecFwk::ElementName element;
    element.SetBundleName("com.ohos.test");
    want.SetElement(element);

    pTestServiceExtension->OnStart(want);
    pTestServiceExtension->OnStop();
    pTestServiceExtension->OnCommand(want, false, 1);
    pTestServiceExtension->OnConnect(want);
    pTestServiceExtension->OnConnect(want);
    pTestServiceExtension->OnDisconnect(want);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}
} // AbilityRuntime
} // OHOS
