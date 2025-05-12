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

#include "form_runtime/cj_form_extension_object.h"
#include "hilog_tag_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace AbilityRuntime {

struct CJFormExtAbilityFuncs {
    int64_t (*createCjFormExtAbility)(const char* name);
    void (*cjFormExtAbilityOnAddForm)(int64_t id, WantHandle want);
    void (*cjFormExtAbilityOnStop)(int64_t id);
};
} // namespace AbilityRuntime
} // namespace OHOS

namespace {
static OHOS::AbilityRuntime::CJFormExtAbilityFuncs g_cjFuncs {};
static const int32_t CJ_OBJECT_ERR_CODE = -1;
} // namespace

namespace OHOS {
namespace AbilityRuntime {

char* CreateCStringFromString(const std::string& source)
{
    if (source.size() == 0) {
        return nullptr;
    }
    size_t length = source.size() + 1;
    auto res = static_cast<char*>(malloc(length));
    if (res == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "null res");
        return nullptr;
    }
    if (strcpy_s(res, length, source.c_str()) != 0) {
        free(res);
        TAG_LOGE(AAFwkTag::FORM_EXT, "Strcpy failed");
        return nullptr;
    }
    return res;
}


int32_t CJFormExtensionObject::Init(const std::string& abilityName)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "called");

    if (g_cjFuncs.createCjFormExtAbility == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "createCjFormExtAbility is not registered");
        return CJ_OBJECT_ERR_CODE;
    }

    cjID_ = g_cjFuncs.createCjFormExtAbility(abilityName.c_str());
    if (cjID_ == 0) {
        TAG_LOGE(AAFwkTag::FORM_EXT,
            "Failed to Init CjFormExtAbility: %{public}s is not registered", abilityName.c_str());
        return CJ_OBJECT_ERR_CODE;
    }

    return 0;
}

void CJFormExtensionObject::OnAddForm(const AAFwk::Want &want)
{
    if (g_cjFuncs.cjFormExtAbilityOnAddForm == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "cjFormExtAbilityOnAddForm is not registered");
        return;
    }

    WantHandle wantHandle = const_cast<AAFwk::Want*>(&want);

    g_cjFuncs.cjFormExtAbilityOnAddForm(cjID_, wantHandle);
}

void CJFormExtensionObject::OnStop()
{
    if (g_cjFuncs.cjFormExtAbilityOnStop == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "cjFormExtAbilityOnStop is not registered");
        return;
    }

    g_cjFuncs.cjFormExtAbilityOnStop(cjID_);
}

extern "C" {
CJ_EXPORT void FFIRegisterCJFormExtAbilityFuncs(void (*registerFunc)(CJFormExtAbilityFuncs*))
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "FFIRegisterCJExtAbilityFuncs start");
    if (g_cjFuncs.createCjFormExtAbility != nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "Repeated registration for cj functions of createCjFormExtAbility");
        return;
    }

    if (registerFunc == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "FFIRegisterCJFormExtAbilityFuncs failed, registerFunc is nullptr");
        return;
    }

    registerFunc(&g_cjFuncs);
    TAG_LOGD(AAFwkTag::FORM_EXT, "FFIRegisterCJFormExtAbilityFuncs end");
}
} // extern "C"
} // namespace AbilityRuntime
} // namespace OHOS
