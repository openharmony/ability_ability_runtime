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

import Context from 'application.Context'
import {ExtensionAbilityInfo}  from 'bundleManager.ExtensionAbilityInfo'
import { Configuration } from '@ohos.app.ability.Configuration'
import { HapModuleInfo } from 'bundleManager.HapModuleInfo'

export default class ExtensionContext extends Context {
    static {
        loadLibrary("context_ani");
    }
    extensionAbilityInfo: ExtensionAbilityInfo;
    config: Configuration;
    currentHapModuleInfo: HapModuleInfo;
    native constructor();
    constructor(config: Configuration, extensionAbilityInfo: ExtensionAbilityInfo, currentHapModuleInfo: HapModuleInfo) {
        super();
        this.config = config;
        this.extensionAbilityInfo = extensionAbilityInfo;
        this.currentHapModuleInfo = currentHapModuleInfo;
    }
}