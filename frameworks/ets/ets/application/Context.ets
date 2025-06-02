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

import BaseContext from 'application.BaseContext'
import ApplicationContext from 'application.ApplicationContext'
import EventHub from 'application.EventHub';
import contextConstant from '@ohos.app.ability.contextConstant'
import { ApplicationInfo } from 'bundleManager.ApplicationInfo'
import resmgr from '@ohos.resourceManager'
import { AsyncCallback } from '@ohos.base';
import { BusinessError } from '@ohos.base';
import AsyncCallbackWrapper from '../utils/AbilityUtils';

export class Context extends BaseContext {
    static {
        loadLibrary("context_ani");
    }
    area: contextConstant.AreaMode = contextConstant.AreaMode.EL1;
    filesDir: string = "";
    tempDir: string = "";
    preferencesDir: string = "";
    databaseDir: string = "";
    cacheDir: string = "";
    applicationInfo: ApplicationInfo;
    eventHub: EventHub = new EventHub();
    resourceManager: resmgr.ResourceManager;
    processName: string = "";
    native constructor();
    constructor(applicationInfo: ApplicationInfo, resourceManager: resmgr.ResourceManager) {
        super();
        this.applicationInfo = applicationInfo;
        this.resourceManager = resourceManager;
    }

    public native getApplicationContextSync(): ApplicationContext;
    public native createModuleResourceManagerSync(bundleName: string, moduleName: string): resmgr.ResourceManager;
    public native nativeGetGroupDir(dataGroupID: string, callback: AsyncCallbackWrapper<string>): void;

    getApplicationContext(): ApplicationContext {
        return this.getApplicationContextSync();
    }

    createModuleResourceManager(bundleName: string, moduleName: string): resmgr.ResourceManager {
        return this.createModuleResourceManagerSync(bundleName, moduleName);
    }

  getGroupDir(dataGroupID: string, callback: AsyncCallback<string>): void {
    let myCall = new AsyncCallbackWrapper<string>(callback);
    taskpool.execute((): void => {
      this.nativeGetGroupDir(dataGroupID, myCall);
    });
  }

  getGroupDir(dataGroupID: string): Promise<string> {
    return new Promise<string>((resolve: (data: string) => void, reject: (err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackWrapper<string>((err: BusinessError<void>, data: string) => {
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeGetGroupDir(dataGroupID, myCall);
      });
    });
  }
}