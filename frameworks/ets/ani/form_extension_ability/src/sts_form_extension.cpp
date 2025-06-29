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

#include "sts_form_extension.h"

#include <sstream>
#include <vector>

#include "ability_info.h"
#include "ani.h"
#include "ani_common_want.h"
#include "form_provider_data.h"
#include "form_runtime/form_extension_provider_client.h"
#include "hilog_tag_wrapper.h"
#include "sts_form_extension_context.h"
#include "connection_manager.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* FORM_BINDING_DATA_CLASS_NAME =
    "L@ohos/app/form/formBindingData/formBindingData/FormBindingDataInner;";
constexpr const char* RECORD_CLASS_NAME = "Lescompat/Record;";
}

STSFormExtension *STSFormExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "call___%{public}d", runtime->GetLanguage());
    return new STSFormExtension(static_cast<STSRuntime &>(*runtime));
}

const STSRuntime &STSFormExtension::GetSTSRuntime()
{
    return stsRuntime_;
}

STSFormExtension::STSFormExtension(STSRuntime &stsRuntime) : stsRuntime_(stsRuntime) {}

STSFormExtension::~STSFormExtension()
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "destructor");
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return;
    }
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "stsAbilityObj_ null");
        return;
    }
    if (stsAbilityObj_->aniRef) {
        env->GlobalReference_Delete(stsAbilityObj_->aniRef);
    }
}

void STSFormExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "Init call");
    if (record == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "null localAbilityRecord");
        return;
    }
    auto abilityInfo = record->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "null abilityInfo");
        return;
    }
    FormExtension::Init(record, application, handler, token);

    std::string srcPath;
    GetSrcPath(srcPath);

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    TAG_LOGD(AAFwkTag::FORM_EXT,
        "moduleName:%{public}s,srcPath:%{public}s,"
        "compileMode :%{public}d",
        moduleName.c_str(), srcPath.c_str(), abilityInfo_->compileMode);

    BindContext(abilityInfo, record->GetWant(), moduleName, srcPath);
    TAG_LOGI(AAFwkTag::FORM_EXT, "Init End");
}

void STSFormExtension::GetSrcPath(std::string &srcPath)
{
    if (!Extension::abilityInfo_->isModuleJson) {
        srcPath.append(Extension::abilityInfo_->package);
        srcPath.append("/assets/js/");
        if (!Extension::abilityInfo_->srcPath.empty()) {
            srcPath.append(Extension::abilityInfo_->srcPath);
        }
        srcPath.append("/").append(Extension::abilityInfo_->name).append(".abc");
        return;
    }

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

void STSFormExtension::UpdateFormExtensionObj(
    std::shared_ptr<AbilityInfo> &abilityInfo, const std::string &moduleName, const std::string &srcPath)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "UpdateFormExtensionObj call");
    stsAbilityObj_ = stsRuntime_.LoadModule(moduleName, srcPath, abilityInfo->hapPath,
        abilityInfo->compileMode == AppExecFwk::CompileMode::ES_MODULE, false, abilityInfo_->srcEntrance);
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "null stsAbilityObj_");
        return;
    }
    TAG_LOGI(AAFwkTag::FORM_EXT, "UpdateFormExtensionObj End");
}

void STSFormExtension::BindContext(std::shared_ptr<AbilityInfo> &abilityInfo, std::shared_ptr<AAFwk::Want> want,
    const std::string &moduleName, const std::string &srcPath)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "BindContext call");

    UpdateFormExtensionObj(abilityInfo, moduleName, srcPath);

    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return;
    }
    if (stsAbilityObj_ == nullptr || want == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "null stsAbilityObj_ or abilityContext_ or want");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "get context error");
        return;
    }
    ani_ref contextObj = CreateStsFormExtensionContext(env, context);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Create context obj error");
        return;
    }
    ani_ref contextGlobalRef = nullptr;
    ani_field field = nullptr;
    ani_status status = ANI_ERROR;

    if ((status = env->GlobalReference_Create(contextObj, &contextGlobalRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "context", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
    }

    if ((status = env->Object_SetField_Ref(stsAbilityObj_->aniObj, field, contextGlobalRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "status : %{public}d", status);
    }

    TAG_LOGI(AAFwkTag::FORM_EXT, "BindContext End");
}

std::string STSFormExtension::ANIUtils_ANIStringToStdString(ani_env *env, ani_string ani_str)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "ANIUtils_ANIStringToStdString Call");
    ani_size strSize;
    if (ANI_OK != env->String_GetUTF8Size(ani_str, &strSize)) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "String_GetUTF8Size Failed");
        return "";
    }

    std::vector<char> buffer(strSize + 1);
    char *utf8_buffer = buffer.data();

    ani_size bytes_written = 0;
    if (ANI_OK != env->String_GetUTF8(ani_str, utf8_buffer, strSize + 1, &bytes_written)) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "String_GetUTF8 Failed");
        return "";
    }

    utf8_buffer[bytes_written] = '\0';
    std::string content = std::string(utf8_buffer);
    TAG_LOGI(AAFwkTag::FORM_EXT, "ANIUtils_ANIStringToStdString End");
    return content;
}

bool STSFormExtension::ConvertFromDataProxies(
    ani_env *env, ani_object arrayValue, std::vector<FormDataProxy> &formDataProxies)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "ConvertFromDataProxies Call");
    ani_status status = ANI_OK;
    if (arrayValue == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "arrayValue null");
        return false;
    }

    ani_double length;
    if (ANI_OK != env->Object_GetPropertyByName_Double(arrayValue, "length", &length)) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_GetPropertyByName_Double length Failed");
        return false;
    }

    int proxyLength = int(length);
    for (int i = 0; i < proxyLength; i++) {
        FormDataProxy formDataProxy("", "");
        ani_ref stringEntryRef;
        if (ANI_OK !=
            env->Object_CallMethodByName_Ref(arrayValue, "$_get", "I:Lstd/core/Object;", &stringEntryRef, (ani_int)i)) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "Object_CallMethodByName_Ref _get Failed");
            return false;
        }

        ani_field key;
        if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "key", &key)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindField status : %{public}d", status);
            return false;
        }

        ani_ref keyRef;
        if ((status = env->Object_GetField_Ref(static_cast<ani_object>(stringEntryRef), key, &keyRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "Object_GetField_Ref status : %{public}d", status);
            return false;
        }

        formDataProxy.key = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(keyRef));

        ani_field subscriberId;
        if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "subscriberId", &subscriberId)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindField status : %{public}d", status);
            return false;
        }

        ani_ref subscriberIdRef;
        status = env->Object_GetField_Ref(static_cast<ani_object>(stringEntryRef), subscriberId, &subscriberIdRef);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "Object_GetField_Ref status : %{public}d", status);
            return false;
        }

        formDataProxy.subscribeId = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(subscriberIdRef));
        formDataProxies.push_back(formDataProxy);
    }
    TAG_LOGI(AAFwkTag::FORM_EXT, "ConvertFromDataProxies End");
    return true;
}

sptr<IRemoteObject> STSFormExtension::OnConnect(const OHOS::AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    Extension::OnConnect(want);
    if (providerRemoteObject_ == nullptr) {
        TAG_LOGD(AAFwkTag::FORM_EXT, "null providerRemoteObject");
        sptr<FormExtensionProviderClient> providerClient = new (std::nothrow) FormExtensionProviderClient();
        std::shared_ptr<STSFormExtension> formExtension =
            std::static_pointer_cast<STSFormExtension>(shared_from_this());
        providerClient->SetOwner(formExtension);
        providerRemoteObject_ = providerClient->AsObject();
    }
    return providerRemoteObject_;
}

OHOS::AppExecFwk::FormProviderInfo STSFormExtension::OnCreate(const OHOS::AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnCreate call");

    OHOS::AppExecFwk::FormProviderInfo formProviderInfo;
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return formProviderInfo;
    }

    ani_object aniWant = OHOS::AppExecFwk::WrapWant(env, want);
    if (aniWant == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "null aniWant");
        return formProviderInfo;
    }

    ani_ref nativeResult;
    if (!CallNativeFormMethod(env, aniWant, nativeResult)) {
        return formProviderInfo;
    }

    AppExecFwk::FormProviderData formData;
    std::vector<FormDataProxy> formDataProxies;
    if (ExtractFormData(env, nativeResult, formData, formDataProxies)) {
        formProviderInfo.SetFormData(formData);
        if (!formDataProxies.empty()) {
            formProviderInfo.SetFormDataProxies(formDataProxies);
        }
    }

    TAG_LOGI(AAFwkTag::FORM_EXT, "OnCreate End");
    return formProviderInfo;
}

bool STSFormExtension::CallNativeFormMethod(ani_env *env, ani_object aniWant, ani_ref &nativeResult)
{
    ani_status status = ANI_OK;

    ani_method function;
    if ((status = env->Class_FindMethod(stsAbilityObj_->aniCls, "onAddForm",
        "L@ohos/app/ability/Want/Want;:L@ohos/app/form/formBindingData/formBindingData/FormBindingData;",
        &function))) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod status: %{public}d", status);
        return false;
    }

    status = env->Object_CallMethod_Ref(stsAbilityObj_->aniObj, function, &nativeResult, aniWant);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_CallMethod_Ref status: %{public}d", status);
        return false;
    }

    return true;
}

bool STSFormExtension::ExtractFormData(ani_env *env, ani_ref nativeResult, AppExecFwk::FormProviderData &formData,
    std::vector<FormDataProxy> &formDataProxies)
{
    ani_status status = ANI_OK;

    ani_class cls{};
    status = env->FindClass(FORM_BINDING_DATA_CLASS_NAME, &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "FindClass status: %{public}d", status);
        return false;
    }

    ani_method data{};
    status = env->Class_FindMethod(cls, "<get>data", nullptr, &data);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod data status: %{public}d", status);
        return false;
    }

    ani_ref dataRef;
    status = env->Object_CallMethod_Ref(static_cast<ani_object>(nativeResult), data, &dataRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_CallMethod_Ref data status: %{public}d", status);
        return false;
    }

    std::string dataStr = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(dataRef));
    formData = AppExecFwk::FormProviderData(dataStr);

    ani_method proxies;
    status = env->Class_FindMethod(cls, "<get>proxies", nullptr, &proxies);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod proxies status: %{public}d", status);
        return true;
    }

    ani_ref proxiesRef;
    status = env->Object_CallMethod_Ref(static_cast<ani_object>(nativeResult), proxies, &proxiesRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_CallMethod_Ref proxies status: %{public}d", status);
        return true;
    }

    ani_boolean isUndefined = true;
    if ((status = env->Reference_IsUndefined(proxiesRef, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Reference_IsUndefined status: %{public}d", status);
    }

    if (!isUndefined && proxiesRef != nullptr) {
        ConvertFromDataProxies(env, static_cast<ani_object>(proxiesRef), formDataProxies);
    }

    return true;
}

ani_status STSFormExtension::ANIUtils_FormIdToAniString(ani_env *env, int64_t formId, ani_string &formIdStr)
{
    ani_status status = ANI_OK;
    std::string str = std::to_string(formId);
    ani_string formIdStrTmp;
    if ((status = env->String_NewUTF8(str.c_str(), str.size(), &formIdStrTmp))) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "String_NewUTF8 status : %{public}d", status);
        return status;
    }
    formIdStr = formIdStrTmp;
    return status;
}

void STSFormExtension::OnDestroy(const int64_t formId)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnDestroy formId: %{public}" PRId64, formId);
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return;
    }
    ani_status status = ANI_OK;

    ani_string formIdStr;
    if (ANIUtils_FormIdToAniString(env, formId, formIdStr) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "formId change failed.");
        return;
    }

    ani_method function;
    if ((status = env->Class_FindMethod(stsAbilityObj_->aniCls, "onRemoveForm", "Lstd/core/String;:V", &function))) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod status : %{public}d", status);
        return;
    }

    status = env->Object_CallMethod_Void(stsAbilityObj_->aniObj, function, formIdStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_New status : %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnDestroy End");
}

void STSFormExtension::OnEvent(const int64_t formId, const std::string &message)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnEvent formId: %{public}" PRId64, formId);
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return;
    }
    ani_status status = ANI_OK;

    ani_string formIdStr;
    if (ANIUtils_FormIdToAniString(env, formId, formIdStr) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "formId change failed.");
        return;
    }
    ani_string aniMessage;
    if ((status = env->String_NewUTF8(message.c_str(), message.size(), &aniMessage))) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "String_NewUTF8 status : %{public}d", status);
        return;
    }
    ani_method function;
    if ((status = env->Class_FindMethod(
        stsAbilityObj_->aniCls, "onFormEvent", "Lstd/core/String;Lstd/core/String;:V", &function))) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod status : %{public}d", status);
        return;
    }

    status = env->Object_CallMethod_Void(stsAbilityObj_->aniObj, function, formIdStr, aniMessage);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_New status : %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnEvent End");
}

void STSFormExtension::OnUpdate(const int64_t formId, const AAFwk::WantParams &wantParams)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnUpdate formId: %{public}" PRId64, formId);
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return;
    }
    ani_status status = ANI_OK;

    ani_string formIdStr;
    if (ANIUtils_FormIdToAniString(env, formId, formIdStr) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "formId change failed.");
        return;
    }

    ani_ref aniWantParams = OHOS::AppExecFwk::WrapWantParams(env, wantParams);

    ani_method function;
    if ((status = env->Class_FindMethod(
        stsAbilityObj_->aniCls, "onUpdateForm", "Lstd/core/String;Lescompat/Record;:V", &function))) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod status : %{public}d", status);
        return;
    }
    status = env->Object_CallMethod_Void(
        stsAbilityObj_->aniObj, function, formIdStr, static_cast<ani_object>(aniWantParams));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_New status : %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnUpdate End");
}

void STSFormExtension::OnCastToNormal(const int64_t formId)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnCastToNormal formId: %{public}" PRId64, formId);
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return;
    }
    ani_status status = ANI_OK;

    ani_string formIdStr;
    if (ANIUtils_FormIdToAniString(env, formId, formIdStr) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "formId change failed.");
        return;
    }

    ani_method function;
    if ((status = env->Class_FindMethod(
        stsAbilityObj_->aniCls, "onCastToNormalForm", "Lstd/core/String;:V", &function))) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod status : %{public}d", status);
        return;
    }

    status = env->Object_CallMethod_Void(stsAbilityObj_->aniObj, function, formIdStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_New status : %{public}d", status);
        return;
    }
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnCastToNormal End");
}

void STSFormExtension::OnVisibilityChange(const std::map<int64_t, int32_t> &formEventsMap)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnVisibilityChange call");

    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return;
    }

    ani_method function;
    ani_status status =
        env->Class_FindMethod(stsAbilityObj_->aniCls, "onChangeFormVisibility", "Lescompat/Record;:V", &function);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod status: %{public}d", status);
        return;
    }

    ani_object recordObject = {};
    if (!CreateAndFillRecordObject(env, formEventsMap, recordObject)) {
        TAG_LOGW(AAFwkTag::FORM_EXT, "formEventsMap empty");
    }

    status = env->Object_CallMethod_Void(stsAbilityObj_->aniObj, function, recordObject);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_CallMethod_Void status: %{public}d", status);
        return;
    }

    TAG_LOGI(AAFwkTag::FORM_EXT, "OnVisibilityChange End");
}

bool STSFormExtension::CreateAndFillRecordObject(ani_env *env, const std::map<int64_t, int32_t> &formEventsMap,
    ani_object &recordObject)
{
    ani_status status = ANI_OK;

    ani_class recordCls;
    status = env->FindClass(RECORD_CLASS_NAME, &recordCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "FindClass failed status: %{public}d", status);
        return false;
    }

    ani_method objectMethod;
    if ((status = env->Class_FindMethod(recordCls, "<ctor>", ":V", &objectMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod constructor failed: %{public}d", status);
        return false;
    }

    if ((status = env->Object_New(recordCls, objectMethod, &recordObject)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_New failed: %{public}d", status);
        return false;
    }

    ani_method recordSetMethod;
    status = env->Class_FindMethod(recordCls, "$_set", "Lstd/core/Object;Lstd/core/Object;:V", &recordSetMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Class_FindMethod set failed: %{public}d", status);
        return false;
    }

    for (auto iter = formEventsMap.begin(); iter != formEventsMap.end(); ++iter) {
        std::string key = std::to_string(iter->first);
        ani_string ani_key;
        ani_int ani_value = iter->second;

        if ((status = env->String_NewUTF8(key.c_str(), key.length(), &ani_key)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "String_NewUTF8 key failed status : %{public}d", status);
            return false;
        }

        static const char *className = "Lstd/core/Int;";
        ani_class persion_cls;
        if (ANI_OK != env->FindClass(className, &persion_cls)) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "Not found ");
            return false;
        }
        ani_method personInfoCtor;
        env->Class_FindMethod(persion_cls, "<ctor>", "I:V", &personInfoCtor);
        ani_object personInfoObj;
        env->Object_New(persion_cls, personInfoCtor, &personInfoObj, ani_value);

        if ((status = env->Object_CallMethod_Void(recordObject, recordSetMethod, ani_key, personInfoObj)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "Object_CallMethod_Void failed status : %{public}d", status);
            return false;
        }
    }

    return true;
}

void STSFormExtension::OnStop()
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "OnStop begin");

    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "env null");
        return;
    }

    ani_ref nameRef;
    ani_status status = env->Object_GetFieldByName_Ref(
        static_cast<ani_object>(stsAbilityObj_->aniRef), "onStop", &nameRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Object_GetFieldByName status: %{public}d, %{public}p, %{public}p",
            status, stsAbilityObj_->aniRef, stsAbilityObj_->aniObj);
        return;
    }
    
    ani_ref result;
    status = env->FunctionalObject_Call(static_cast<ani_fn_object>(nameRef), 0, nullptr, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "FunctionalObject_Call status: %{public}d", status);
        return;
    }

    bool ret = ConnectionManager::GetInstance().DisconnectCaller(GetContext()->GetToken());
    if (ret) {
        ConnectionManager::GetInstance().ReportConnectionLeakEvent(getpid(), gettid());
        TAG_LOGI(AAFwkTag::FORM_EXT, "disconnected failed");
        return;
    }

    TAG_LOGI(AAFwkTag::FORM_EXT, "OnStop End");
}
} // namespace AbilityRuntime
} // namespace OHOS
