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

#ifndef OHOS_ABILITY_RUNTIME_STS_CONTEXT_UTIL_H
#define OHOS_ABILITY_RUNTIME_STS_CONTEXT_UTIL_H

#include "sts_runtime.h"
#include "context.h"

namespace OHOS {
namespace AbilityRuntime {
namespace ContextUtil {
static void ApplicationInfo() {}

static void BindExtensionInfo() {}

static void BindApplicationCtx(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef)
{
    // bind parent context field:applicationContext
    ani_field applicationContextField;
    if (aniEnv->Class_FindField(contextClass, "applicationContext", &applicationContextField) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed");
    }
    ani_ref applicationContextRef = reinterpret_cast<ani_ref>(applicationCtxRef);
    TAG_LOGI(AAFwkTag::APPKIT, "applicationContextRef: %{public}p", applicationContextRef);
    if (aniEnv->Object_SetField_Ref(contextObj, applicationContextField, applicationContextRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
    }
}

static void BindParentProperty(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    // bind parent context property
    ani_method areaSetter;
    if (ANI_OK != aniEnv->Class_FindMethod(contextClass, "<set>area", nullptr, &areaSetter)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find set area failed");
    }
    auto area = context->GetArea();
    TAG_LOGI(AAFwkTag::APPKIT, "ani area:%{public}d", area);
    if (ANI_OK != aniEnv->Object_CallMethod_Void(contextObj, areaSetter, ani_int(area))) {
        TAG_LOGE(AAFwkTag::APPKIT, "call set area failed");
    }

    ani_method filesDirSetter;
    if (ANI_OK != aniEnv->Class_FindMethod(contextClass, "<set>filesDir", nullptr, &filesDirSetter)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find set filesDir failed");
    }
    std::string filesDir = context->GetFilesDir();
    TAG_LOGI(AAFwkTag::APPKIT, "ani filesDir:%{public}s", filesDir.c_str());
    ani_string filesDir_string{};
    aniEnv->String_NewUTF8(filesDir.c_str(), filesDir.size(), &filesDir_string);
    if (ANI_OK != aniEnv->Object_CallMethod_Void(contextObj, filesDirSetter, filesDir_string)) {
        TAG_LOGE(AAFwkTag::APPKIT, "call set filesDir failed");
    }

    ani_method tempDirSetter;
    if (ANI_OK != aniEnv->Class_FindMethod(contextClass, "<set>tempDir", nullptr, &tempDirSetter)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find set tempDir failed");
    }
    auto tempDir = context->GetTempDir();
    TAG_LOGI(AAFwkTag::APPKIT, "ani tempDir:%{public}s", tempDir.c_str());
    ani_string tempDir_string{};
    aniEnv->String_NewUTF8(tempDir.c_str(), tempDir.size(), &tempDir_string);
    if (ANI_OK != aniEnv->Object_CallMethod_Void(contextObj, tempDirSetter, tempDir_string)) {
        TAG_LOGE(AAFwkTag::APPKIT, "call set tempDir failed");
    }

    ApplicationInfo();
}

static void StsCreatContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef, std::shared_ptr<Context> context)
{
    BindApplicationCtx(aniEnv, contextClass, contextObj, applicationCtxRef);
    BindParentProperty(aniEnv, contextClass, contextObj, context);
}

static void StsCreatExtensionContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef, std::shared_ptr<Context> context)
{
    StsCreatContext(aniEnv, contextClass, contextObj, applicationCtxRef, context);
    BindExtensionInfo();
}
}
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STS_CONTEXT_UTIL_H
