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

#include "ets_app_service_extension.h"

#include "ability_business_error.h"
#include "ability_info.h"
#include "ani_common_configuration.h"
#include "ani_common_want.h"
#include "remote_object_taihe_ani.h"
#include "configuration_utils.h"
#include "ets_app_service_extension_context.h"
#include "ets_extension_context.h"
#include "ets_runtime.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"

#ifdef WINDOWS_PLATFORM
#define ETS_EXPORT __declspec(dllexport)
#else
#define ETS_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
namespace {
constexpr const char *APP_SERVICE_EXTENSION_CONTEXT_CLASS_NAME =
    "Lapplication/AppServiceExtensionContext/AppServiceExtensionContext;";
constexpr const char *ON_CREATE_SIGNATURE = "L@ohos/app/ability/Want/Want;:V";
constexpr const char *VOID_SIGNATURE = ":V";
constexpr const char *ON_CONNECT_SIGNATURE = "L@ohos/app/ability/Want/Want;:Lstd/core/Object;";
constexpr const char *ON_DISCONNECT_SIGNATURE = "L@ohos/app/ability/Want/Want;:V";
constexpr const char *ON_REQUEST_SIGNATURE = "L@ohos/app/ability/Want/Want;I:V";
constexpr const char *ON_CONFIGURATION_UPDATE_SIGNATURE = "L@ohos/app/ability/Configuration/Configuration;:V";
} // namespace

EtsAppServiceExtension* EtsAppServiceExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new EtsAppServiceExtension(static_cast<ETSRuntime&>(*runtime));
}

EtsAppServiceExtension::EtsAppServiceExtension(ETSRuntime& etsRuntime) : etsRuntime_(etsRuntime) {}
EtsAppServiceExtension::~EtsAppServiceExtension()
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "EtsAppServiceExtension destory");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }
}

void EtsAppServiceExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    AppServiceExtension::Init(record, application, handler, token);
    std::string srcPath = "";
    GetSrcPath(srcPath);
    if (srcPath.empty()) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "get srcPath failed");
        return;
    }

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    etsObj_ = etsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo_->hapPath, abilityInfo_->compileMode == CompileMode::ES_MODULE,
        false, abilityInfo_->srcEntrance);
    if (etsObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null jsObj_");
        return;
    }

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    BindContext(env);
}

void EtsAppServiceExtension::OnStart(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnStart");
    Extension::OnStart(want);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "env not found Ability.ets");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null wantRef");
        return;
    }

    CallObjectMethod(false, "onCreate", ON_CREATE_SIGNATURE, wantRef);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "end");
}

void EtsAppServiceExtension::OnStop()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnStop");
    AppServiceExtension::OnStop();
    CallObjectMethod(false, "onDestroy", VOID_SIGNATURE);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "end");
}

sptr<IRemoteObject> EtsAppServiceExtension::OnConnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnConnect");
    Extension::OnConnect(want);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        return nullptr;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null wantRef");
        return nullptr;
    }
    ani_ref result = CallObjectMethod(true, "onConnect", ON_CONNECT_SIGNATURE, wantRef);
    auto obj = reinterpret_cast<ani_object>(result);
    auto remoteObj = AniGetNativeRemoteObject(env, obj);
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "remoteObj null");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "end");
    return remoteObj;
}

void EtsAppServiceExtension::OnDisconnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnDisconnect");
    Extension::OnDisconnect(want);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null wantRef");
        return;
    }
    CallObjectMethod(false, "onDisconnect", ON_DISCONNECT_SIGNATURE, wantRef);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "end");
}

void EtsAppServiceExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnCommand");
    Extension::OnCommand(want, restart, startId);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null wantRef");
        return;
    }
    ani_int iStartId = static_cast<ani_int>(startId);
    CallObjectMethod(false, "onRequest", ON_REQUEST_SIGNATURE, wantRef, iStartId);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "end");
    return;
}

ani_ref EtsAppServiceExtension::CallObjectMethod(bool withResult, const char *name, const char *signature, ...)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(etsObj_->aniCls, name, signature, &method)) != ANI_OK) {
        return nullptr;
    }
    if (method == nullptr) {
        return nullptr;
    }
    ani_ref res = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(etsObj_->aniObj, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "status : %{public}d", status);
            return nullptr;
        }
        va_end(args);
        return res;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsObj_->aniObj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "status : %{public}d", status);
    }
    va_end(args);
    return nullptr;
}

ani_object EtsAppServiceExtension::CreateETSContext(ani_env *env, std::shared_ptr<AppServiceExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "CreateETSContext");
    return CreateEtsAppServiceExtensionContext(env, context);
}

void EtsAppServiceExtension::BindContext(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "BindContext");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Want info is null or env is null");
        return;
    }
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to get context");
        return;
    }
    ani_object contextObj = CreateETSContext(env, context);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null contextObj");
        return;
    }
    ani_field contextField;
    auto status = env->Class_FindField(etsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Class_GetField context failed");
        return;
    }
    ani_ref contextRef = nullptr;
    if (env->GlobalReference_Create(contextObj, &contextRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "GlobalReference_Create contextObj failed");
        return;
    }
    if (env->Object_SetField_Ref(etsObj_->aniObj, contextField, contextRef) != ANI_OK) {
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "Object_SetField_Ref contextObj failed");
    }
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "BindContext end");
}

void EtsAppServiceExtension::OnConfigurationUpdated(const AppExecFwk::Configuration &configuration)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnConfigurationUpdated Call");
    AppServiceExtension::OnConfigurationUpdated(configuration);
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null context");
        return;
    }

    auto contextConfig = context->GetConfiguration();
    if (contextConfig != nullptr) {
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "Config dump: %{public}s", contextConfig->GetName().c_str());
        std::vector<std::string> changeKeyV;
        contextConfig->CompareDifferent(changeKeyV, configuration);
        if (!changeKeyV.empty()) {
            contextConfig->Merge(changeKeyV, configuration);
        }
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "Config dump after merge: %{public}s", contextConfig->GetName().c_str());
    }
    ConfigurationUpdated();
}

void EtsAppServiceExtension::ConfigurationUpdated()
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "ConfigurationUpdated");
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "env nullptr");
        return;
    }
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null context");
        return;
    }
    auto fullConfig = context->GetConfiguration();
    if (fullConfig == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null configuration");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_object aniConfiguration = OHOS::AppExecFwk::WrapConfiguration(env, *fullConfig);
    status = env->Object_CallMethodByName_Void(
        etsObj_->aniObj, "onConfigurationUpdate", ON_CONFIGURATION_UPDATE_SIGNATURE, aniConfiguration);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "CALL Object_CallMethod failed, status: %{public}d", status);
        return;
    }
    ani_ref contextRef = nullptr;
    if ((status = env->Object_GetFieldByName_Ref(etsObj_->aniObj, "context", &contextRef)) != ANI_OK ||
        contextRef == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to get field, status : %{public}d", status);
        return;
    }
    ani_class cls = nullptr;
    ani_field configField = nullptr;
    if ((status = env->FindClass(APP_SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to find class, status : %{public}d", status);
        return;
    }
    if ((status = env->Class_FindField(cls, "config", &configField)) != ANI_OK || configField == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to find field, status : %{public}d", status);
        return;
    }
    if ((status = env->Object_SetFieldByName_Ref(reinterpret_cast<ani_object>(contextRef), "config",
        aniConfiguration)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to set field, status : %{public}d", status);
        return;
    }
}

void EtsAppServiceExtension::GetSrcPath(std::string &srcPath)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "called");
    if (!Extension::abilityInfo_->srcEntrance.empty()) {
        srcPath.append(Extension::abilityInfo_->moduleName + "/");
        srcPath.append(Extension::abilityInfo_->srcEntrance);
        auto pos = srcPath.rfind(".");
        if (pos != std::string::npos) {
            srcPath.erase(pos);
            srcPath.append(".abc");
        }
    }
}
} // AbilityRuntime
} // OHOS

ETS_EXPORT extern "C" OHOS::AbilityRuntime::AppServiceExtension *OHOS_ETS_App_Service_Extension_Create(
    const std::unique_ptr<OHOS::AbilityRuntime::Runtime> &runtime)
{
    return OHOS::AbilityRuntime::EtsAppServiceExtension::Create(runtime);
}