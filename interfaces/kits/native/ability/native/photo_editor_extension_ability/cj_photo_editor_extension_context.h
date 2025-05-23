/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_CJ_PHOTO_EDITOR_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_CJ_PHOTO_EDITOR_EXTENSION_CONTEXT_H

#include "photo_editor_extension_context.h"
#include "cj_ui_extension_context.h"
#include "image_packer.h"
#include "cj_context.h"

namespace OHOS {
namespace AbilityRuntime {
class CJPhotoEditorExtensionContext : public CJUIExtensionContext {
public:
    explicit CJPhotoEditorExtensionContext(const std::shared_ptr<PhotoEditorExtensionContext> &context)
        : CJUIExtensionContext(context), context_(context)
    {}

    virtual ~CJPhotoEditorExtensionContext() = default;

    void SetWant(const std::shared_ptr<AAFwk::Want> &want)
    {
        want_ = want;
    }

    int32_t SaveEditedContentWithUri(const std::string& uri, AAFwk::Want& want);
    int32_t SaveEditedContentWithImage(std::shared_ptr<Media::PixelMap> image, const Media::PackOption& packOption,
        AAFwk::Want& want);
    std::shared_ptr<PhotoEditorExtensionContext> GetContext()
    {
        return context_.lock();
    }
private:
    std::weak_ptr<PhotoEditorExtensionContext> context_;
    std::weak_ptr<AAFwk::Want> want_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CJ_PHOTO_EDITOR_EXTENSION_CONTEXT_H
