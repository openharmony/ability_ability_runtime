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

#include "native_engine/native_engine.h"

extern const char _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_JS_START[];
extern const char _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_JS_END[];
extern const char _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_ABC_START[];
extern const char _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_ABC_END[];

static napi_module _module = {
    .nm_version = 0,
    .nm_filename = "app/ability/libphotoeditorextensionability_napi.so/photo_editor_extension_ability.js",
    .nm_modname = "app.ability.PhotoEditorExtensionAbility",
};
extern "C" __attribute__((constructor)) void NAPI_app_ability_PhotoEditorExtensionAbility_AutoRegister()
{
    napi_module_register(&_module);
}

extern "C" __attribute__((visibility("default"))) void
NAPI_app_ability_PhotoEditorExtensionAbility_GetJSCode(const char **buf, int *bufLen)
{
    if (buf != nullptr) {
        *buf = _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_JS_START;
    }

    if (bufLen != nullptr) {
        *bufLen = _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_JS_END - _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_JS_START;
    }
}

extern "C" __attribute__((visibility("default"))) void
NAPI_app_ability_PhotoEditorExtensionAbility_GetABCCode(const char **buf, int *buflen)
{
    if (buf != nullptr) {
        *buf = _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_ABC_START;
    }
    if (buflen != nullptr) {
        *buflen = _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_ABC_END - _BINARY_PHOTO_EDITOR_EXTENSION_ABILITY_ABC_START;
    }
}