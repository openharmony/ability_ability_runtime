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

#include "cj_photo_editor_extension_context.h"

#include "cj_ui_extension_object.h"
#include "cj_photo_editor_extension_impl.h"
#include "cj_common_ffi.h"
#include "pixel_map_impl.h"
#include "image_ffi.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
int32_t CJPhotoEditorExtensionContext::SaveEditedContentWithUri(const std::string& uri, AAFwk::Want& want)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "SaveEditedContentWithUri begin");
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
        return static_cast<int32_t>(PhotoEditorErrorCode::ERROR_CODE_INTERNAL_ERROR);
    }

    if (want_.lock() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "PhotoEditorExtensionContext does not call SetWant");
        return static_cast<int32_t>(PhotoEditorErrorCode::ERROR_CODE_INTERNAL_ERROR);
    }

    PhotoEditorErrorCode errCode = context->SaveEditedContent(uri, want);
    return static_cast<int32_t>(errCode);
}

int32_t CJPhotoEditorExtensionContext::SaveEditedContentWithImage(std::shared_ptr<Media::PixelMap> image,
    const Media::PackOption& packOption, AAFwk::Want& want)
{
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
        return static_cast<int32_t>(PhotoEditorErrorCode::ERROR_CODE_INTERNAL_ERROR);
    }

    if (want_.lock() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "PhotoEditorExtensionContext does not call SetWant");
        return static_cast<int32_t>(PhotoEditorErrorCode::ERROR_CODE_INTERNAL_ERROR);
    }

    PhotoEditorErrorCode errCode = context->SaveEditedContent(image, packOption, want);
    return static_cast<int32_t>(errCode);
}

extern "C" {
CJ_EXPORT int32_t FFIPhotoExtAbilityGetContext(ExtAbilityHandle extAbility, int64_t* id)
{
    auto ability = static_cast<CJPhotoEditorExtensionImpl*>(extAbility);
    if (ability == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, extAbility is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (id == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, param id is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto context = ability->GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::Create<CJPhotoEditorExtensionContext>(context);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, extAbilityContext is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    ability->SetCjContext(cjContext);
    *id = cjContext->GetID();
    return SUCCESS_CODE;
}

CJ_EXPORT int32_t FFIPhotoExtCtxSaveEditedContentWithUri(int64_t id, const char* uri, WantHandle want)
{
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param uri is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::GetData<CJPhotoEditorExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    return cjContext->SaveEditedContentWithUri(std::string(uri), *actualWant);
}

static Media::PackOption ParseCPackOption(const CPackingOption& option)
{
    return Media::PackOption {
        .format = option.format,
        .quality = option.quality,
        .desiredDynamicRange = Media::EncodeDynamicRange(option.desiredDynamicRange),
        .needsPackProperties = option.needsPackProperties,
    };
}

CJ_EXPORT int32_t FFIPhotoExtCtxSaveEditedContentWithImage(int64_t id, int64_t imageId, CPackingOption option,
    WantHandle want)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::GetData<CJPhotoEditorExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto pixelMapImpl = OHOS::FFI::FFIData::GetData<Media::PixelMapImpl>(imageId);
    if (pixelMapImpl == nullptr || pixelMapImpl->GetRealPixelMap() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetPixelMapImpl result is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);

    return cjContext->SaveEditedContentWithImage(pixelMapImpl->GetRealPixelMap(), ParseCPackOption(option),
        *actualWant);
}
}
} // namespace AbilityRuntime
} // namespace OHOS
