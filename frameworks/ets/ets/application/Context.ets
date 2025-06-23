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

export class Context extends BaseContext {
  static {
    loadLibrary("context_ani");
  }
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
  public native getApplicationContextSync(): ApplicationContext;
  private native switchArea(mode: contextConstant.AreaMode): void;
  private native getArea(): contextConstant.AreaMode;

  getApplicationContext(): ApplicationContext {
    return this.getApplicationContextSync();
  }

  set area(mode: contextConstant.AreaMode) {
    this.switchArea(mode);
  }

  get area(): contextConstant.AreaMode {
    return this.getArea();
  }
}
