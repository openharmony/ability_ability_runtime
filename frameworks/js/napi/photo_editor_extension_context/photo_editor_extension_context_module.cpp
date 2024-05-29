/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

extern const char _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_JS_START[];
extern const char _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_JS_END[];
extern const char _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_ABC_START[];
extern const char _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_ABC_END[];

static napi_module _module = {
    .nm_version = 0,
    .nm_filename = "application/libphotoeditorextensioncontext_napi.so/photo_editor_extension_context.js",
    .nm_modname = "application.PhotoEditorExtensionContext",
};
extern "C" __attribute__((constructor)) void NAPI_application_PhotoEditorExtensionContext_AutoRegister()
{
    napi_module_register(&_module);
}

extern "C" __attribute__((visibility("default"))) void
NAPI_application_PhotoEditorExtensionContext_GetJSCode(const char **buf, int *bufLen)
{
    if (buf != nullptr) {
        *buf = _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_JS_START;
    }

    if (bufLen != nullptr) {
        *bufLen = _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_JS_END - _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_JS_START;
    }
}

// ability_context JS register
extern "C" __attribute__((visibility("default"))) void
NAPI_application_PhotoEditorExtensionContext_GetABCCode(const char **buf, int *buflen)
{
    if (buf != nullptr) {
        *buf = _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_ABC_START;
    }
    if (buflen != nullptr) {
        *buflen = _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_ABC_END - _BINARY_PHOTO_EDITOR_EXTENSION_CONTEXT_ABC_START;
    }
}
