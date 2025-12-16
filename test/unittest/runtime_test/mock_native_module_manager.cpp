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

#include <gtest/gtest.h>
#include "mock_native_module_manager.h"

namespace {
    bool g_mockGetLdNamespaceName = false;
    bool g_mockDefaultNamespaceName = false;
    std::string g_mockGetLdNamespaceNameNameStr = "";
}

void MockGetLdNamespaceName(bool namespaceRet)
{
    g_mockGetLdNamespaceName = namespaceRet;
}

void MockDefaultNamespaceName(bool defaultNamespaceRet)
{
    g_mockDefaultNamespaceName = defaultNamespaceRet;
}

void MockGetLdNamespaceNameStr(const std::string &namespaceNameStr)
{
    g_mockGetLdNamespaceNameNameStr = namespaceNameStr;
}

void MockResetModuleManagerState()
{
    g_mockGetLdNamespaceName = false;
    g_mockDefaultNamespaceName = false;
    g_mockGetLdNamespaceNameNameStr = "";
}

bool NativeModuleManager::GetLdNamespaceName(const std::string &moduleName, std::string &nsName)
{
    nsName = g_mockGetLdNamespaceNameNameStr;
    if (moduleName == "default") {
        return g_mockDefaultNamespaceName;
    } else {
        return g_mockGetLdNamespaceName;
    }
}