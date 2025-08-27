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
 
#ifndef OHOS_ABILITY_RUNTIME_ETS_PHOTO_EDITOR_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_ETS_PHOTO_EDITOR_EXTENSION_CONTEXT_H

#include "photo_editor_extension_context.h"
#include "native_engine/native_engine.h"
#include "image_packer.h"
#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
ani_object CreateEtsPhotoEditorExtensionContext(ani_env *env, std::shared_ptr<PhotoEditorExtensionContext> context);

class EtsPhotoEditorExtensionContext {
public:
    explicit EtsPhotoEditorExtensionContext(const std::shared_ptr<PhotoEditorExtensionContext> &context)
        : context_(context)
    {}

    virtual ~EtsPhotoEditorExtensionContext() = default;

    static void Finalizer(ani_env* aniEnv, ani_object obj);

    static EtsPhotoEditorExtensionContext* GetEtsPhotoEditorExtensionContext(ani_env* aniEnv, ani_object obj);

    static void SaveEditedContentWithUri(ani_env* aniEnv, ani_object obj, ani_string uri, ani_object callback);

    static void SaveEditedContentWithImage(ani_env* aniEnv, ani_object obj, ani_object imageObj,
        ani_object optionObj, ani_object callback);

    std::weak_ptr<PhotoEditorExtensionContext> GetAbilityContext()
    {
        return context_;
    }
private:
    void OnSaveEditedContentWithUri(ani_env* aniEnv, ani_object obj, ani_string uri, ani_object callback);

    void OnSaveEditedContentWithImage(ani_env* aniEnv, ani_object obj, ani_object imageObj,
        ani_object optionObj, ani_object callback);

    bool UnwrapPackOption(ani_env* aniEnv, ani_object optionObj, Media::PackOption &packOption);

private:
    std::weak_ptr<PhotoEditorExtensionContext> context_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ETS_PHOTO_EDITOR_EXTENSION_CONTEXT_H