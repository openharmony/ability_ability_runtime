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

import BaseContext from './BaseContext'
import ApplicationContext from './ApplicationContext'
import EventHub from './EventHub';
import contextConstant from '@ohos.app.ability.contextConstant'
import { ApplicationInfo } from 'bundleManager.ApplicationInfo'
import resmgr from '@ohos.resourceManager'

export class Context extends BaseContext {
    public nativeContext:long;
    area: contextConstant.AreaMode = contextConstant.AreaMode.EL1;
    filesDir: string = "";
    tempDir: string = "";
    applicationInfo: ApplicationInfo;
    eventHub: EventHub = new EventHub();
    resourceManager: resmgr.ResourceManager;

    public native getApplicationContextSync(): ApplicationContext;

    getApplicationContext(): ApplicationContext {
        return this.getApplicationContextSync();
    }
}