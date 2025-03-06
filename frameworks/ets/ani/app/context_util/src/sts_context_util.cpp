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

#include "sts_context_util.h"

#include "common_fun_ani.h"
#include "application_context.h"
#include "hilog_tag_wrapper.h"
#include "resmgr_ani.h"

namespace OHOS {
namespace AbilityRuntime {
namespace ContextUtil {
void BindApplicationCtx(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef)
{
    // bind parent context field:applicationContext
    ani_field applicationContextField;
    if (aniEnv->Class_FindField(contextClass, "applicationContext", &applicationContextField) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed");
        return;
    }
    ani_ref applicationContextRef = reinterpret_cast<ani_ref>(applicationCtxRef);
    TAG_LOGI(AAFwkTag::APPKIT, "applicationContextRef: %{public}p", applicationContextRef);
    if (aniEnv->Object_SetField_Ref(contextObj, applicationContextField, applicationContextRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void BindApplicationInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    TAG_LOGE(AAFwkTag::APPKIT, "ywz BindApplicationInfo");
    ani_field applicationInfoField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "applicationInfo", &applicationInfoField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find find applicationInfo failed");
        return;
    }
    auto appInfo = context->GetApplicationInfo();
    ani_object appInfoObj = AppExecFwk::CommonFunAni::ConvertApplicationInfo(aniEnv, *appInfo);
    if (aniEnv->Object_SetField_Ref(contextObj, applicationInfoField,
        reinterpret_cast<ani_ref>(appInfoObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void BindResourceManager(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    TAG_LOGE(AAFwkTag::APPKIT, "ywz BindResourceManager");
    ani_field resourceManagerField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "resourceManager", &resourceManagerField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find find resourceManager failed");
        return;
    }
    auto resourceManager = context->GetResourceManager();
    ani_object resourceMgrObj = Global::Resource::ResMgrAddon::CreateResMgr(aniEnv, "", resourceManager, context);
    if (aniEnv->Object_SetField_Ref(contextObj, resourceManagerField,
        reinterpret_cast<ani_ref>(resourceMgrObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void BindParentProperty(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    BindApplicationInfo(aniEnv, contextClass, contextObj, context);
    BindResourceManager(aniEnv, contextClass, contextObj, context);

    // bind parent context property
    ani_field areaField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "area", &areaField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find area failed");
        return;
    }
    auto area = context->GetArea();
    TAG_LOGI(AAFwkTag::APPKIT, "ani area:%{public}d", area);
    if (aniEnv->Object_SetField_Int(contextObj, areaField, (ani_int)area) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Int failed");
        return;
    }

    ani_field filesDirField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "filesDir", &filesDirField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find filesDir failed");
        return;
    }
    auto filesDir = context->GetFilesDir();
    TAG_LOGI(AAFwkTag::APPKIT, "ani filesDir:%{public}s", filesDir.c_str());
    ani_string filesDir_string{};
    aniEnv->String_NewUTF8(filesDir.c_str(), filesDir.size(), &filesDir_string);
    if (aniEnv->Object_SetField_Ref(contextObj, filesDirField, reinterpret_cast<ani_ref>(filesDir_string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }

    ani_field tempDirField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "tempDir", &tempDirField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find find tempDir failed");
        return;
    }
    auto tempDir = context->GetTempDir();
    TAG_LOGI(AAFwkTag::APPKIT, "ani tempDir:%{public}s", tempDir.c_str());
    ani_string tempDir_string{};
    aniEnv->String_NewUTF8(tempDir.c_str(), tempDir.size(), &tempDir_string);
    if (aniEnv->Object_SetField_Ref(contextObj, tempDirField, reinterpret_cast<ani_ref>(tempDir_string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void StsCreatContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef, std::shared_ptr<Context> context)
{
    BindApplicationCtx(aniEnv, contextClass, contextObj, applicationCtxRef);
    BindParentProperty(aniEnv, contextClass, contextObj, context);
}

void BindExtensionInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<AbilityRuntime::Context> context, std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo)
{
    TAG_LOGE(AAFwkTag::APPKIT, "ywz BindExtensionInfo");
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (abilityInfo && hapModuleInfo) {
        auto isExist = [&abilityInfo](const AppExecFwk::ExtensionAbilityInfo& info) {
            TAG_LOGD(AAFwkTag::CONTEXT, "%{public}s, %{public}s", info.bundleName.c_str(), info.name.c_str());
            return info.bundleName == abilityInfo->bundleName && info.name == abilityInfo->name;
        };
        auto infoIter = std::find_if(
            hapModuleInfo->extensionInfos.begin(), hapModuleInfo->extensionInfos.end(), isExist);
        if (infoIter == hapModuleInfo->extensionInfos.end()) {
            TAG_LOGE(AAFwkTag::CONTEXT, "set extensionAbilityInfo fail");
            return;
        }
        ani_field extensionAbilityInfoField;
        if (ANI_OK != aniEnv->Class_FindField(contextClass, "extensionAbilityInfo", &extensionAbilityInfoField)) {
            TAG_LOGE(AAFwkTag::APPKIT, "find extensionAbilityInfo failed");
            return;
        }
        ani_object extAbilityInfoObj = AppExecFwk::CommonFunAni::ConvertExtensionInfo(aniEnv, *infoIter);
        if (aniEnv->Object_SetField_Ref(contextObj, extensionAbilityInfoField,
            reinterpret_cast<ani_ref>(extAbilityInfoObj)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
            return;
        }
    }
}

void StsCreatExtensionContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef, std::shared_ptr<AbilityRuntime::ExtensionContext> context)
{
    StsCreatContext(aniEnv, contextClass, contextObj, applicationCtxRef, context);
    BindExtensionInfo(aniEnv, contextClass, contextObj, context, context->GetAbilityInfo());
}
}
} // namespace AbilityRuntime
} // namespace OHOS
