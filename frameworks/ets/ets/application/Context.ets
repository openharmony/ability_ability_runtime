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
import contextConstant from '@ohos.app.ability.contextConstant'
import { ApplicationInfo } from 'bundleManager.ApplicationInfo'
import resmgr from '@ohos.resourceManager'

class Cleaner {
  public ptr: long = 0;
  constructor(ptr: long) {
    this.ptr = ptr;
  }
  native clean(): void;
}
export function callback(cleaner: Cleaner): void {
  cleaner.clean();
}
let destroyRegister = new FinalizationRegistry<Cleaner>(callback);
let unregisterToken = new object();

export class Context extends BaseContext {
  static {
    loadLibrary("context_ani");
  }
  etsContextPtr: long = 0;
  private cleaner: Cleaner | null = null;
  filesDir: string = "";
  tempDir: string = "";
  preferencesDir: string = "";
  databaseDir: string = "";
  cacheDir: string = "";
  applicationInfo: ApplicationInfo;
  resourceManager: resmgr.ResourceManager;
  native constructor();
  constructor(applicationInfo: ApplicationInfo, resourceManager: resmgr.ResourceManager) {
      super();
      this.applicationInfo = applicationInfo;
      this.resourceManager = resourceManager;
  }
  private setEtsContextPtr(ptr: long) {
    if (this.etsContextPtr == 0) {
      this.etsContextPtr = ptr;
    }
    this.registerCleaner(this.etsContextPtr);
  }
  registerCleaner(ptr: long): void {
    this.cleaner = new Cleaner(ptr);
    destroyRegister.register(this, this.cleaner!, unregisterToken);
  }
  unregisterCleaner(): void {
    destroyRegister.unregister(unregisterToken);
  }
  public native getApplicationContextSync(): ApplicationContext;
  public native createModuleResourceManagerSync(bundleName: string, moduleName: string): resmgr.ResourceManager;
  private native switchArea(mode: contextConstant.AreaMode): void;
  private native getArea(): contextConstant.AreaMode;

  getApplicationContext(): ApplicationContext {
    return this.getApplicationContextSync();
  }

  createModuleResourceManager(bundleName: string, moduleName: string): resmgr.ResourceManager {
    return this.createModuleResourceManagerSync(bundleName, moduleName);
  }

  set area(mode: contextConstant.AreaMode) {
    this.switchArea(mode);
  }

  get area(): contextConstant.AreaMode {
    return this.getArea();
  }
}
