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

#include "sts_context_utils.h"

#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "application_context.h"
#include "application_context_manager.h"
#include "common_fun_ani.h"
#include "hilog_tag_wrapper.h"
#include "resourceManager.h"
#include "sts_error_utils.h"

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
    if (aniEnv->Object_SetField_Ref(contextObj, applicationContextField, applicationContextRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void BindApplicationInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    ani_field applicationInfoField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "applicationInfo", &applicationInfoField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find applicationInfo failed");
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
    ani_field resourceManagerField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "resourceManager", &resourceManagerField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find resourceManager failed");
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
    ani_enum_item areaModeItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToSts(
        aniEnv, "L@ohos/app/ability/contextConstant/contextConstant/AreaMode;", area, areaModeItem);

    if (aniEnv->Object_SetField_Ref(contextObj, areaField, (ani_ref)areaModeItem) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Int failed");
        return;
    }

    ani_field filesDirField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "filesDir", &filesDirField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find filesDir failed");
        return;
    }
    auto filesDir = context->GetFilesDir();
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

ani_object GetApplicationContextSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj)
{
    auto appContextObj = ApplicationContextManager::GetApplicationContextManager().GetStsGlobalObject(env);
    if (appContextObj != nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContextObj is not nullptr");
        return appContextObj->aniObj;
    }
    ThrowStsInvalidParamError(env, "appContextObj null");
    return {};
}
}
} // namespace AbilityRuntime
} // namespace OHOS
